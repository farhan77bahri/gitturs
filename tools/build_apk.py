#!/usr/bin/env python3
"""Build a signed Android APK wrapping web/index.html in a WebView."""
from __future__ import annotations

import hashlib
import io
import os
import struct
import zipfile
import zlib
from datetime import datetime, timezone
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.hazmat.primitives.serialization import Encoding, pkcs7
from cryptography.x509.oid import NameOID

ROOT = Path("/home/user/gitturs")
WEB = ROOT / "web" / "index.html"
ICON = ROOT / "web" / "icon.png"
ORIG = Path("/tmp/apk_extract")
OUT = ROOT / "AIChat-dark.apk"

# ---------------------------------------------------------------------------
# LEB128 / alignment
# ---------------------------------------------------------------------------

def uleb(n: int) -> bytes:
    out = bytearray()
    while True:
        b = n & 0x7F
        n >>= 7
        if n:
            out.append(b | 0x80)
        else:
            out.append(b)
            return bytes(out)


def align(buf: bytearray, n: int) -> None:
    while len(buf) % n:
        buf.append(0)


def mutf8(s: str) -> bytes:
    # ASCII-only strings in this APK; still emit MUTF-8 terminator.
    return s.encode("utf-8") + b"\x00"


# ---------------------------------------------------------------------------
# Dalvik opcodes (format helpers)
# ---------------------------------------------------------------------------

def op_return_void() -> bytes:
    return bytes([0x0E, 0x00])


def op_const4(dst: int, val: int) -> bytes:
    return bytes([0x12, ((val & 0xF) << 4) | (dst & 0xF)])


def op_const(dst: int, val: int) -> bytes:
    return bytes([0x14, dst]) + struct.pack("<I", val & 0xFFFFFFFF)


def op_const_string(dst: int, sidx: int) -> bytes:
    return bytes([0x1A, dst]) + struct.pack("<H", sidx)


def op_new_instance(dst: int, tidx: int) -> bytes:
    return bytes([0x22, dst]) + struct.pack("<H", tidx)


def op_move_result_object(dst: int) -> bytes:
    return bytes([0x0C, dst])


def op_invoke(kind: int, argc: int, method: int, regs: list[int]) -> bytes:
    # kind: 0x6e virtual, 0x70 direct, 0x6f super
    regs = list(regs) + [0] * 5
    g, c, d, e, f = regs[0], regs[1], regs[2], regs[3], regs[4]
    # If argc < 5, G is unused (first register is C). Standard encoding:
    # registers listed as {C, D, E, F, G} for A=count.
    # Our callers pass regs in order C,D,E,F,G.
    c, d, e, f, g = (list(regs[:argc]) + [0] * 5)[:5]
    return bytes([kind, ((argc & 0xF) << 4) | (g & 0xF)]) + struct.pack("<H", method) + bytes(
        [(c & 0xF) | ((d & 0xF) << 4), (e & 0xF) | ((f & 0xF) << 4)]
    )


# ---------------------------------------------------------------------------
# DEX builder
# ---------------------------------------------------------------------------

class Dex:
    def __init__(self):
        self.strings: list[str] = []
        self.smap: dict[str, int] = {}
        self.types: list[str] = []
        self.tmap: dict[str, int] = {}
        self.protos: list[tuple] = []  # (shorty, ret, [params])
        self.pmap: dict[tuple, int] = {}
        self.methods: list[tuple] = []  # (cls, name, proto_key)
        self.mmap: dict[tuple, int] = {}

    def S(self, s: str) -> int:
        if s not in self.smap:
            self.smap[s] = len(self.strings)
            self.strings.append(s)
        return self.smap[s]

    def T(self, desc: str) -> int:
        self.S(desc)
        if desc not in self.tmap:
            self.tmap[desc] = len(self.types)
            self.types.append(desc)
        return self.tmap[desc]

    def P(self, ret: str, params: list[str]) -> int:
        shorty = {"V": "V", "Z": "Z", "I": "I"}.get(ret, "L") + "".join(
            {"V": "V", "Z": "Z", "I": "I"}.get(p, "L") for p in params
        )
        self.S(shorty)
        self.T(ret)
        for p in params:
            self.T(p)
        key = (shorty, ret, tuple(params))
        if key not in self.pmap:
            self.pmap[key] = len(self.protos)
            self.protos.append(key)
        return self.pmap[key]

    def M(self, cls: str, name: str, ret: str, params: list[str]) -> int:
        self.T(cls)
        self.S(name)
        self.P(ret, params)
        key = (cls, name, ret, tuple(params))
        if key not in self.mmap:
            self.mmap[key] = len(self.methods)
            self.methods.append(key)
        return self.mmap[key]


def build_dex() -> bytes:
    d = Dex()

    ACT = "Landroid/app/Activity;"
    MAIN = "Lcom/zchat/app/MainActivity;"
    BUNDLE = "Landroid/os/Bundle;"
    WV = "Landroid/webkit/WebView;"
    WS = "Landroid/webkit/WebSettings;"
    CTX = "Landroid/content/Context;"
    VIEW = "Landroid/view/View;"
    STR = "Ljava/lang/String;"
    OBJ = "Ljava/lang/Object;"

    # Ensure types/methods exist
    d.T(OBJ)
    d.T(MAIN)
    d.T(ACT)
    m_act_init = d.M(ACT, "<init>", "V", [])
    m_oncreate_super = d.M(ACT, "onCreate", "V", [BUNDLE])
    m_set_content = d.M(ACT, "setContentView", "V", [VIEW])
    m_wv_init = d.M(WV, "<init>", "V", [CTX])
    m_get_settings = d.M(WV, "getSettings", WS, [])
    m_load_url = d.M(WV, "loadUrl", "V", [STR])
    m_bg = d.M(WV, "setBackgroundColor", "V", ["I"])
    m_js = d.M(WS, "setJavaScriptEnabled", "V", ["Z"])
    m_dom = d.M(WS, "setDomStorageEnabled", "V", ["Z"])
    m_file = d.M(WS, "setAllowFileAccess", "V", ["Z"])
    m_uni = d.M(WS, "setAllowUniversalAccessFromFileURLs", "V", ["Z"])
    m_ffa = d.M(WS, "setAllowFileAccessFromFileURLs", "V", ["Z"])
    m_mix = d.M(WS, "setMixedContentMode", "V", ["I"])
    m_overview = d.M(WS, "setLoadWithOverviewMode", "V", ["Z"])
    m_wide = d.M(WS, "setUseWideViewPort", "V", ["Z"])
    url_s = d.S("file:///android_asset/index.html")
    d.S("MainActivity.java")

    # Freeze maps (string order must be sorted in DEX!)
    # Spec: string_ids lexicographically ordered by MUTF-8 contents.
    strings_sorted = sorted(d.strings)
    new_smap = {s: i for i, s in enumerate(strings_sorted)}
    # types sorted by string index
    types_sorted = sorted(d.types, key=lambda t: new_smap[t])
    new_tmap = {t: i for i, t in enumerate(types_sorted)}
    # protos sorted by return type idx then param type idxs
    protos_sorted = sorted(d.protos, key=lambda k: (new_tmap[k[1]], [new_tmap[p] for p in k[2]]))
    new_pmap = {k: i for i, k in enumerate(protos_sorted)}
    # methods sorted by class idx, name idx, proto idx
    methods_sorted = sorted(
        d.methods,
        key=lambda k: (new_tmap[k[0]], new_smap[k[1]], new_pmap[(None and 0) or proto_key(k, d)]),
    )

    def proto_of(mkey):
        shorty = {"V": "V", "Z": "Z", "I": "I"}.get(mkey[2], "L") + "".join(
            {"V": "V", "Z": "Z", "I": "I"}.get(p, "L") for p in mkey[3]
        )
        return (shorty, mkey[2], mkey[3])

    methods_sorted = sorted(
        d.methods,
        key=lambda k: (new_tmap[k[0]], new_smap[k[1]], new_pmap[proto_of(k)]),
    )
    new_mmap = {k: i for i, k in enumerate(methods_sorted)}

    def Mi(cls, name, ret, params):
        return new_mmap[(cls, name, ret, tuple(params))]

    def Ti(desc):
        return new_tmap[desc]

    def Si(s):
        return new_smap[s]

    # rebuild method indexes used in bytecode
    i_act_init = Mi(ACT, "<init>", "V", [])
    i_oncreate_super = Mi(ACT, "onCreate", "V", [BUNDLE])
    i_set_content = Mi(ACT, "setContentView", "V", [VIEW])
    i_wv_init = Mi(WV, "<init>", "V", [CTX])
    i_get_settings = Mi(WV, "getSettings", WS, [])
    i_load_url = Mi(WV, "loadUrl", "V", [STR])
    i_bg = Mi(WV, "setBackgroundColor", "V", ["I"])
    i_js = Mi(WS, "setJavaScriptEnabled", "V", ["Z"])
    i_dom = Mi(WS, "setDomStorageEnabled", "V", ["Z"])
    i_file = Mi(WS, "setAllowFileAccess", "V", ["Z"])
    i_uni = Mi(WS, "setAllowUniversalAccessFromFileURLs", "V", ["Z"])
    i_ffa = Mi(WS, "setAllowFileAccessFromFileURLs", "V", ["Z"])
    i_mix = Mi(WS, "setMixedContentMode", "V", ["I"])
    i_overview = Mi(WS, "setLoadWithOverviewMode", "V", ["Z"])
    i_wide = Mi(WS, "setUseWideViewPort", "V", ["Z"])
    i_url = Si("file:///android_asset/index.html")
    i_wv_type = Ti(WV)

    # <init> : registers=1 ins=1 outs=1
    code_init = bytearray()
    code_init += op_invoke(0x70, 1, i_act_init, [0])  # invoke-direct {v0=p0}
    code_init += op_return_void()

    # onCreate : registers=8  (v0..v5, p0=v6, p1=v7) ins=2 outs=2
    # v0 = WebView, v1 = WebSettings, v2 = 1, v3 = url, v4 = color, v5 = 0
    P0, P1 = 6, 7
    code_on = bytearray()
    code_on += op_invoke(0x6F, 2, i_oncreate_super, [P0, P1])  # super.onCreate
    code_on += op_new_instance(0, i_wv_type)
    code_on += op_invoke(0x70, 2, i_wv_init, [0, P0])
    code_on += op_invoke(0x6E, 1, i_get_settings, [0])
    code_on += op_move_result_object(1)
    code_on += op_const4(2, 1)
    code_on += op_invoke(0x6E, 2, i_js, [1, 2])
    code_on += op_invoke(0x6E, 2, i_dom, [1, 2])
    code_on += op_invoke(0x6E, 2, i_file, [1, 2])
    code_on += op_invoke(0x6E, 2, i_uni, [1, 2])
    code_on += op_invoke(0x6E, 2, i_ffa, [1, 2])
    code_on += op_invoke(0x6E, 2, i_overview, [1, 2])
    code_on += op_invoke(0x6E, 2, i_wide, [1, 2])
    code_on += op_const4(5, 0)
    code_on += op_invoke(0x6E, 2, i_mix, [1, 5])
    code_on += op_const(4, 0xFF0E0E0E)
    code_on += op_invoke(0x6E, 2, i_bg, [0, 4])
    code_on += op_const_string(3, i_url)
    code_on += op_invoke(0x6E, 2, i_load_url, [0, 3])
    code_on += op_invoke(0x6E, 2, i_set_content, [P0, 0])
    code_on += op_return_void()

    def wrap_code(registers, ins, outs, insns: bytes) -> bytes:
        if len(insns) % 2:
            raise ValueError("odd insn bytes")
        insns_units = len(insns) // 2
        header = struct.pack(
            "<HHHHII",
            registers,
            ins,
            outs,
            0,  # tries
            0,  # debug
            insns_units,
        )
        return header + insns

    code_init_item = wrap_code(1, 1, 1, bytes(code_init))
    code_on_item = wrap_code(8, 2, 2, bytes(code_on))

    # class_data for MainActivity
    # direct methods: <init>  (constructor)
    # virtual methods: onCreate
    def method_enc(idx, flags, code_off_placeholder=0):
        return uleb(idx) + uleb(flags) + uleb(code_off_placeholder)

    # We'll patch code offsets later; first layout sections.

    # ---- layout DEX ----
    # We'll collect data blobs with offsets relative to start of file.
    HEADER_SIZE = 0x70
    n_str = len(strings_sorted)
    n_type = len(types_sorted)
    n_proto = len(protos_sorted)
    n_meth = len(methods_sorted)
    n_class = 1

    # string_ids off
    off = HEADER_SIZE
    string_ids_off = off
    off += n_str * 4
    type_ids_off = off
    off += n_type * 4
    proto_ids_off = off
    off += n_proto * 12
    field_ids_off = off  # 0 fields
    method_ids_off = off
    off += n_meth * 8
    class_defs_off = off
    off += n_class * 32
    data_off = off
    # align data to 4
    while off % 4:
        off += 1
    data_off = off

    data = bytearray()
    map_items = []  # (type, size, offset)

    def data_pos():
        return data_off + len(data)

    def emit(b: bytes):
        data.extend(b)

    def pad4():
        while (data_off + len(data)) % 4:
            data.append(0)

    # string_data
    string_data_offs = []
    string_data_off0 = data_pos()
    for s in strings_sorted:
        string_data_offs.append(data_pos())
        encoded = s.encode("utf-8")
        emit(uleb(len(s)))  # utf16 length (ASCII == byte length)
        emit(encoded + b"\x00")
    map_items.append((0x2002, n_str, string_data_off0))  # string_data_item

    # type_lists for protos that have params
    pad4()
    typelist_offs = {}
    type_list_count = 0
    type_list_off0 = None
    for shorty, ret, params in protos_sorted:
        if not params:
            continue
        pad4()
        if type_list_off0 is None:
            type_list_off0 = data_pos()
        typelist_offs[(shorty, ret, params)] = data_pos()
        emit(struct.pack("<I", len(params)))
        for p in params:
            emit(struct.pack("<H", new_tmap[p]))
        if len(params) % 2:
            emit(b"\x00\x00")
        type_list_count += 1
    if type_list_count:
        map_items.append((0x1001, type_list_count, type_list_off0))

    # code items
    pad4()
    code_init_off = data_pos()
    emit(code_init_item)
    pad4()
    code_on_off = data_pos()
    emit(code_on_item)
    map_items.append((0x2001, 2, code_init_off))

    # class_data
    # method idx diffs
    init_idx = Mi(MAIN, "<init>", "V", []) if (MAIN, "<init>", "V", tuple()) in new_mmap else None
    # MainActivity only defines <init> and onCreate — they must be in method_ids
    # We need to ADD MainActivity.<init> and MainActivity.onCreate to method list!
    # Currently methods only include referenced methods, not our own if we didn't M() them.

    # Fix: we invoked Activity.<init> and Activity.onCreate, but we need
    # Lcom/zchat/app/MainActivity; methods in class_data pointing to method_ids
    # of MainActivity's own methods. Those must exist in method_ids.

    # We did NOT add MainActivity.<init> / onCreate to method_ids. Must rebuild with them.
    raise_if_missing = True
    return _build_dex_with_own_methods()


def proto_key_from(ret, params):
    shorty = {"V": "V", "Z": "Z", "I": "I"}.get(ret, "L") + "".join(
        {"V": "V", "Z": "Z", "I": "I"}.get(p, "L") for p in params
    )
    return (shorty, ret, tuple(params))


def _build_dex_with_own_methods() -> bytes:
    """Single-pass DEX writer with sorted ids."""
    ACT = "Landroid/app/Activity;"
    MAIN = "Lcom/zchat/app/MainActivity;"
    BUNDLE = "Landroid/os/Bundle;"
    WV = "Landroid/webkit/WebView;"
    WS = "Landroid/webkit/WebSettings;"
    CTX = "Landroid/content/Context;"
    VIEW = "Landroid/view/View;"
    STR = "Ljava/lang/String;"
    OBJ = "Ljava/lang/Object;"

    needed_strings = set()
    needed_types = set()
    needed_protos = []  # (ret, params)
    needed_methods = []  # (cls, name, ret, params)

    def add_type(t):
        needed_types.add(t)
        needed_strings.add(t)

    def add_proto(ret, params):
        shorty = {"V": "V", "Z": "Z", "I": "I"}.get(ret, "L") + "".join(
            {"V": "V", "Z": "Z", "I": "I"}.get(p, "L") for p in params
        )
        needed_strings.add(shorty)
        add_type(ret)
        for p in params:
            add_type(p)
        item = (shorty, ret, tuple(params))
        if item not in needed_protos:
            needed_protos.append(item)
        return item

    def add_method(cls, name, ret, params):
        add_type(cls)
        needed_strings.add(name)
        add_proto(ret, params)
        item = (cls, name, ret, tuple(params))
        if item not in needed_methods:
            needed_methods.append(item)
        return item

    add_type(OBJ)
    add_type(MAIN)
    add_type(ACT)
    needed_strings.add("MainActivity.java")
    needed_strings.add("file:///android_asset/index.html")

    WIN = "Landroid/view/Window;"
    add_method(ACT, "<init>", "V", [])
    add_method(ACT, "onCreate", "V", [BUNDLE])
    add_method(ACT, "setContentView", "V", [VIEW])
    add_method(ACT, "getWindow", WIN, [])
    add_method(WIN, "setStatusBarColor", "V", ["I"])
    add_method(WIN, "setNavigationBarColor", "V", ["I"])
    add_method(WV, "<init>", "V", [CTX])
    add_method(WV, "getSettings", WS, [])
    add_method(WV, "loadUrl", "V", [STR])
    add_method(WV, "setBackgroundColor", "V", ["I"])
    add_method(WS, "setJavaScriptEnabled", "V", ["Z"])
    add_method(WS, "setDomStorageEnabled", "V", ["Z"])
    add_method(WS, "setAllowFileAccess", "V", ["Z"])
    add_method(WS, "setAllowUniversalAccessFromFileURLs", "V", ["Z"])
    add_method(WS, "setAllowFileAccessFromFileURLs", "V", ["Z"])
    add_method(WS, "setMixedContentMode", "V", ["I"])
    add_method(WS, "setLoadWithOverviewMode", "V", ["Z"])
    add_method(WS, "setUseWideViewPort", "V", ["Z"])
    # own methods
    add_method(MAIN, "<init>", "V", [])
    add_method(MAIN, "onCreate", "V", [BUNDLE])

    strings = sorted(needed_strings)
    smap = {s: i for i, s in enumerate(strings)}
    types = sorted(needed_types, key=lambda t: smap[t])
    tmap = {t: i for i, t in enumerate(types)}
    protos = sorted(needed_protos, key=lambda k: (tmap[k[1]], [tmap[p] for p in k[2]]))
    pmap = {k: i for i, k in enumerate(protos)}
    methods = sorted(needed_methods, key=lambda k: (tmap[k[0]], smap[k[1]], pmap[(
        {"V": "V", "Z": "Z", "I": "I"}.get(k[2], "L") + "".join(
            {"V": "V", "Z": "Z", "I": "I"}.get(p, "L") for p in k[3]
        ),
        k[2],
        k[3],
    )]))
    mmap = {k: i for i, k in enumerate(methods)}

    def M(cls, name, ret, params):
        return mmap[(cls, name, ret, tuple(params))]

    def T(desc):
        return tmap[desc]

    def S(s):
        return smap[s]

    def proto_idx(ret, params):
        shorty = {"V": "V", "Z": "Z", "I": "I"}.get(ret, "L") + "".join(
            {"V": "V", "Z": "Z", "I": "I"}.get(p, "L") for p in params
        )
        return pmap[(shorty, ret, tuple(params))]

    # bytecode
    def inv(kind, argc, mid, regs):
        rr = (list(regs) + [0, 0, 0, 0, 0])[:5]
        c, d, e, f, g = rr
        return bytes([kind, ((argc & 0xF) << 4) | (g & 0xF)]) + struct.pack("<H", mid) + bytes(
            [(c & 0xF) | ((d & 0xF) << 4), (e & 0xF) | ((f & 0xF) << 4)]
        )

    # init: p0=v0
    code_init = inv(0x70, 1, M(ACT, "<init>", "V", []), [0]) + bytes([0x0E, 0x00])

    # onCreate registers=8, p0=v6 p1=v7
    P0, P1 = 6, 7
    WIN = "Landroid/view/Window;"
    b = bytearray()
    b += inv(0x6F, 2, M(ACT, "onCreate", "V", [BUNDLE]), [P0, P1])
    b += inv(0x6E, 1, M(ACT, "getWindow", WIN, []), [P0])
    b += bytes([0x0C, 0])  # move-result-object v0 = Window
    b += bytes([0x14, 4]) + struct.pack("<I", 0xFF0E0E0E)
    b += inv(0x6E, 2, M(WIN, "setStatusBarColor", "V", ["I"]), [0, 4])
    b += inv(0x6E, 2, M(WIN, "setNavigationBarColor", "V", ["I"]), [0, 4])
    b += bytes([0x22, 0]) + struct.pack("<H", T(WV))  # new-instance v0, WebView
    b += inv(0x70, 2, M(WV, "<init>", "V", [CTX]), [0, P0])
    b += inv(0x6E, 1, M(WV, "getSettings", WS, []), [0])
    b += bytes([0x0C, 1])  # move-result-object v1
    b += bytes([0x12, 0x12])  # const/4 v2, 1   (B=1, A=2) -> byte1 = (1<<4)|2 = 0x12
    for meth in (
        M(WS, "setJavaScriptEnabled", "V", ["Z"]),
        M(WS, "setDomStorageEnabled", "V", ["Z"]),
        M(WS, "setAllowFileAccess", "V", ["Z"]),
        M(WS, "setAllowUniversalAccessFromFileURLs", "V", ["Z"]),
        M(WS, "setAllowFileAccessFromFileURLs", "V", ["Z"]),
        M(WS, "setLoadWithOverviewMode", "V", ["Z"]),
        M(WS, "setUseWideViewPort", "V", ["Z"]),
    ):
        b += inv(0x6E, 2, meth, [1, 2])
    b += bytes([0x12, 0x05])  # const/4 v5, 0
    b += inv(0x6E, 2, M(WS, "setMixedContentMode", "V", ["I"]), [1, 5])
    b += bytes([0x14, 4]) + struct.pack("<I", 0xFF0E0E0E)  # const v4, color
    b += inv(0x6E, 2, M(WV, "setBackgroundColor", "V", ["I"]), [0, 4])
    b += bytes([0x1A, 3]) + struct.pack("<H", S("file:///android_asset/index.html"))
    b += inv(0x6E, 2, M(WV, "loadUrl", "V", [STR]), [0, 3])
    b += inv(0x6E, 2, M(ACT, "setContentView", "V", [VIEW]), [P0, 0])
    b += bytes([0x0E, 0x00])
    code_on = bytes(b)

    def code_item(reg, ins, outs, insns):
        return struct.pack("<HHHHII", reg, ins, outs, 0, 0, len(insns) // 2) + insns

    ci = code_item(1, 1, 1, code_init)
    co = code_item(8, 2, 2, code_on)

    HEADER = 0x70
    n_str, n_type, n_proto, n_field, n_meth, n_cls = len(strings), len(types), len(protos), 0, len(methods), 1
    string_ids_off = HEADER
    type_ids_off = string_ids_off + n_str * 4
    proto_ids_off = type_ids_off + n_type * 4
    field_ids_off = proto_ids_off + n_proto * 12
    method_ids_off = field_ids_off + n_field * 8
    class_defs_off = method_ids_off + n_meth * 8
    data_off = class_defs_off + n_cls * 32
    if data_off % 4:
        data_off += 4 - (data_off % 4)

    data = bytearray()

    def pos():
        return data_off + len(data)

    def pad(n=4):
        while pos() % n:
            data.append(0)

    map_items = []

    # string_data
    str_offs = []
    pad(4)
    sd0 = pos()
    for s in strings:
        str_offs.append(pos())
        raw = s.encode("utf-8")
        data.extend(uleb(len(s)))
        data.extend(raw + b"\x00")
    map_items.append((0x2002, n_str, sd0))

    # type lists
    pad(4)
    tl_offs = {}
    tl0 = None
    tlc = 0
    for item in protos:
        shorty, ret, params = item
        if not params:
            tl_offs[item] = 0
            continue
        pad(4)
        if tl0 is None:
            tl0 = pos()
        tl_offs[item] = pos()
        data.extend(struct.pack("<I", len(params)))
        for p in params:
            data.extend(struct.pack("<H", tmap[p]))
        if len(params) % 2:
            data.extend(b"\x00\x00")
        tlc += 1
    if tlc:
        map_items.append((0x1001, tlc, tl0))

    # code
    pad(4)
    code_init_off = pos()
    data.extend(ci)
    pad(4)
    code_on_off = pos()
    data.extend(co)
    map_items.append((0x2001, 2, code_init_off))

    # class_data
    # direct: <init> idx diff from 0
    init_m = M(MAIN, "<init>", "V", [])
    on_m = M(MAIN, "onCreate", "V", [BUNDLE])
    # class_data encodes method_idx_diff in sorted order of method_idx
    # direct methods first (constructors/static/private), then virtual
    # <init> is direct (ACC_CONSTRUCTOR|PUBLIC = 0x10001)
    # onCreate is virtual (PUBLIC = 0x1)
    cd = bytearray()
    cd.extend(uleb(0))  # static fields
    cd.extend(uleb(0))  # instance fields
    cd.extend(uleb(1))  # direct methods
    cd.extend(uleb(1))  # virtual methods
    cd.extend(uleb(init_m) + uleb(0x10001) + uleb(code_init_off))
    cd.extend(uleb(on_m) + uleb(0x1) + uleb(code_on_off))  # first virtual, diff = on_m - 0
    # Wait: virtual method_idx_diff is from 0 as well (separate lists).
    class_data_off = pos()
    data.extend(cd)
    map_items.append((0x2000, 1, class_data_off))

    # map_list last
    pad(4)
    map_off = pos()
    # map must include header/id sections too, sorted by offset
    id_maps = [
        (0x0000, 1, 0),  # header
        (0x0001, n_str, string_ids_off),
        (0x0002, n_type, type_ids_off),
        (0x0003, n_proto, proto_ids_off),
        (0x0005, n_meth, method_ids_off),
        (0x0006, n_cls, class_defs_off),
    ]
    all_maps = id_maps + map_items
    # append map_list itself
    # we need to know map size first: 4 + 12 * (len(all_maps)+1)
    nmap = len(all_maps) + 1
    all_maps.append((0x1000, 1, map_off))
    all_maps.sort(key=lambda x: x[2])
    data.extend(struct.pack("<I", len(all_maps)))
    for t, sz, of in all_maps:
        data.extend(struct.pack("<HHI I", t, 0, sz, of))
    map_items.append((0x1000, 1, map_off))  # not used further

    file_size = data_off + len(data)

    # build id tables
    string_ids = b"".join(struct.pack("<I", o) for o in str_offs)
    type_ids = b"".join(struct.pack("<I", smap[t]) for t in types)
    proto_ids = b""
    for shorty, ret, params in protos:
        proto_ids += struct.pack("<III", smap[shorty], tmap[ret], tl_offs[(shorty, ret, params)])
    method_ids = b""
    for cls, name, ret, params in methods:
        shorty = {"V": "V", "Z": "Z", "I": "I"}.get(ret, "L") + "".join(
            {"V": "V", "Z": "Z", "I": "I"}.get(p, "L") for p in params
        )
        method_ids += struct.pack("<HH I", tmap[cls], proto_idx(ret, params), smap[name])

    class_def = struct.pack(
        "<IIIIIIII",
        T(MAIN),
        0x1,  # public
        T(ACT),
        0,  # interfaces
        S("MainActivity.java"),
        0,  # annotations
        class_data_off,
        0,  # static values
    )

    header = bytearray(HEADER)
    header[0:8] = b"dex\n035\x00"
    # checksum + signature later
    struct.pack_into("<I", header, 32, file_size)
    struct.pack_into("<I", header, 36, HEADER)
    struct.pack_into("<I", header, 40, 0x12345678)
    struct.pack_into("<I", header, 44, 0)  # link_size
    struct.pack_into("<I", header, 48, 0)  # link_off
    struct.pack_into("<I", header, 52, map_off)
    struct.pack_into("<I", header, 56, n_str)
    struct.pack_into("<I", header, 60, string_ids_off)
    struct.pack_into("<I", header, 64, n_type)
    struct.pack_into("<I", header, 68, type_ids_off)
    struct.pack_into("<I", header, 72, n_proto)
    struct.pack_into("<I", header, 76, proto_ids_off)
    struct.pack_into("<I", header, 80, n_field)
    struct.pack_into("<I", header, 84, field_ids_off)
    struct.pack_into("<I", header, 88, n_meth)
    struct.pack_into("<I", header, 92, method_ids_off)
    struct.pack_into("<I", header, 96, n_cls)
    struct.pack_into("<I", header, 100, class_defs_off)
    struct.pack_into("<I", header, 104, file_size - data_off)
    struct.pack_into("<I", header, 108, data_off)

    pad_ids = b"\x00" * (data_off - (class_defs_off + 32))
    body = bytes(header) + string_ids + type_ids + proto_ids + method_ids + class_def + pad_ids + bytes(data)
    assert len(body) == file_size

    sha1 = hashlib.sha1(body[32:]).digest()
    body = body[:12] + sha1 + body[32:]
    csum = zlib.adler32(body[12:]) & 0xFFFFFFFF
    body = body[:8] + struct.pack("<I", csum) + body[12:]
    return body


# ---------------------------------------------------------------------------
# Binary AndroidManifest
# ---------------------------------------------------------------------------

RES_XML = 0x0003
RES_STRING_POOL = 0x0001
RES_XML_RESOURCE_MAP = 0x0180
RES_XML_START_NS = 0x0100
RES_XML_END_NS = 0x0101
RES_XML_START_EL = 0x0102
RES_XML_END_EL = 0x0103

TYPE_NULL = 0x00
TYPE_REF = 0x01
TYPE_STRING = 0x03
TYPE_INT = 0x10
TYPE_BOOL = 0x12

ANDROID_NS = "http://schemas.android.com/apk/res/android"

ATTR_IDS = {
    "theme": 0x01010000,
    "label": 0x01010001,
    "icon": 0x01010002,
    "name": 0x01010003,
    "exported": 0x01010010,
    "minSdkVersion": 0x0101020C,
    "versionCode": 0x0101021B,
    "versionName": 0x0101021C,
    "windowSoftInputMode": 0x0101022B,
    "configChanges": 0x0101001F,
    "targetSdkVersion": 0x01010270,
    "allowBackup": 0x01010280,
    "hardwareAccelerated": 0x010102D3,
    "supportsRtl": 0x010103AF,
    "usesCleartextTraffic": 0x010104EC,
    "compileSdkVersion": 0x01010572,
    "compileSdkVersionCodename": 0x01010573,
}


def utf16_str(s: str) -> bytes:
    chars = s.encode("utf-16le")
    n = len(s)
    return struct.pack("<H", n) + chars + b"\x00\x00"


def build_manifest() -> bytes:
    # string pool: first ATTR_IDS keys (resource map order), then other strings
    attr_names = list(ATTR_IDS.keys())
    other = [
        ".MainActivity",
        "34",
        "3.0",
        "action",
        "activity",
        "android",
        "android.intent.action.MAIN",
        "android.intent.category.LAUNCHER",
        "android.permission.ACCESS_NETWORK_STATE",
        "android.permission.INTERNET",
        "application",
        "category",
        "com.zchat.app",
        ANDROID_NS,
        "intent-filter",
        "manifest",
        "package",
        "platformBuildVersionCode",
        "platformBuildVersionName",
        "uses-permission",
        "uses-sdk",
        "14",
    ]
    strings = attr_names + other
    smap = {s: i for i, s in enumerate(strings)}

    # string pool chunk
    offsets = []
    blob = bytearray()
    for s in strings:
        offsets.append(len(blob))
        blob.extend(utf16_str(s))
    while len(blob) % 4:
        blob.append(0)
    header_size = 28
    pool_size = header_size + 4 * len(strings) + len(blob)
    pool = bytearray()
    pool.extend(struct.pack("<HHI", RES_STRING_POOL, header_size, pool_size))
    pool.extend(struct.pack("<I", len(strings)))  # stringCount
    pool.extend(struct.pack("<I", 0))  # styleCount
    pool.extend(struct.pack("<I", 0))  # flags UTF16
    pool.extend(struct.pack("<I", header_size + 4 * len(strings)))  # stringsStart
    pool.extend(struct.pack("<I", 0))  # stylesStart
    for o in offsets:
        pool.extend(struct.pack("<I", o))
    pool.extend(blob)

    # resource map for first len(ATTR_IDS) strings
    rm_ids = [ATTR_IDS[n] for n in attr_names]
    rm = struct.pack("<HHI", RES_XML_RESOURCE_MAP, 8, 8 + 4 * len(rm_ids))
    rm += b"".join(struct.pack("<I", i) for i in rm_ids)

    def sp(s):
        return smap[s]

    def ns_chunk(start: bool, prefix: str, uri: str, line=2):
        t = RES_XML_START_NS if start else RES_XML_END_NS
        return struct.pack(
            "<HHI I i i i",
            t,
            16,
            24,
            line,
            -1,
            sp(prefix),
            sp(uri),
        )

    def tv(dtype, data):
        return struct.pack("<HBBI", 8, 0, dtype, data & 0xFFFFFFFF)

    def attr(name, dtype, data, raw=-1, ns=True):
        nsi = sp("android") if ns else -1
        if dtype == TYPE_STRING and raw == -1:
            raw = data
        return struct.pack("<iii", nsi, sp(name), raw) + tv(dtype, data)

    def start(name, attrs, line=3):
        body = b"".join(attrs)
        # node header 16 + attrExt 20 + attrs
        size = 16 + 20 + len(body)
        chunk = struct.pack("<HHI I i", RES_XML_START_EL, 16, size, line, -1)
        chunk += struct.pack("<ii", -1, sp(name))  # ns, name
        chunk += struct.pack("<HHH", 20, 20, len(attrs))
        chunk += struct.pack("<HHH", 0, 0, 0)  # id/class/style idx (0 = none, but 0 might mean first attr)
        # Original used 0. Some docs say 0 means none for these if count handled. We'll use 0.
        chunk += body
        return chunk

    def end(name, line=3):
        return struct.pack("<HHI I i i i", RES_XML_END_EL, 16, 24, line, -1, -1, sp(name))

    xml = bytearray()
    xml.extend(ns_chunk(True, "android", ANDROID_NS))
    xml.extend(
        start(
            "manifest",
            [
                attr("versionCode", TYPE_INT, 17),
                attr("versionName", TYPE_STRING, sp("3.0")),
                attr("compileSdkVersion", TYPE_INT, 34),
                attr("compileSdkVersionCodename", TYPE_STRING, sp("14")),
                attr("package", TYPE_STRING, sp("com.zchat.app"), ns=False),
                attr("platformBuildVersionCode", TYPE_INT, 34, ns=False),
                attr("platformBuildVersionName", TYPE_STRING, sp("14"), ns=False),
            ],
        )
    )
    xml.extend(
        start(
            "uses-sdk",
            [
                attr("minSdkVersion", TYPE_INT, 21),
                attr("targetSdkVersion", TYPE_INT, 34),
            ],
        )
    )
    xml.extend(end("uses-sdk"))
    xml.extend(start("uses-permission", [attr("name", TYPE_STRING, sp("android.permission.INTERNET"))]))
    xml.extend(end("uses-permission"))
    xml.extend(
        start(
            "uses-permission",
            [attr("name", TYPE_STRING, sp("android.permission.ACCESS_NETWORK_STATE"))],
        )
    )
    xml.extend(end("uses-permission"))
    xml.extend(
        start(
            "application",
            [
                attr("theme", TYPE_REF, 0x0103000F),  # Theme.Black.NoTitleBar
                attr("label", TYPE_REF, 0x7F060001),
                attr("icon", TYPE_REF, 0x7F050000),
                attr("allowBackup", TYPE_BOOL, 0),
                attr("supportsRtl", TYPE_BOOL, 0xFFFFFFFF),
                attr("usesCleartextTraffic", TYPE_BOOL, 0xFFFFFFFF),
                attr("hardwareAccelerated", TYPE_BOOL, 0xFFFFFFFF),
            ],
        )
    )
    # configChanges: orientation=0x0080, screenSize=0x0400, keyboardHidden=0x0020, uiMode=0x0200, screenLayout=0x0100
    cfg = 0x0080 | 0x0400 | 0x0020 | 0x0200 | 0x0100
    xml.extend(
        start(
            "activity",
            [
                attr("name", TYPE_STRING, sp(".MainActivity")),
                attr("exported", TYPE_BOOL, 0xFFFFFFFF),
                attr("windowSoftInputMode", TYPE_INT, 0x10),  # adjustResize
                attr("configChanges", TYPE_INT, cfg),
            ],
        )
    )
    xml.extend(start("intent-filter", []))
    xml.extend(start("action", [attr("name", TYPE_STRING, sp("android.intent.action.MAIN"))]))
    xml.extend(end("action"))
    xml.extend(start("category", [attr("name", TYPE_STRING, sp("android.intent.category.LAUNCHER"))]))
    xml.extend(end("category"))
    xml.extend(end("intent-filter"))
    xml.extend(end("activity"))
    xml.extend(end("application"))
    xml.extend(end("manifest"))
    xml.extend(ns_chunk(False, "android", ANDROID_NS))

    total = 8 + len(pool) + len(rm) + len(xml)
    out = struct.pack("<HHI", RES_XML, 8, total) + bytes(pool) + rm + bytes(xml)
    return out


# ---------------------------------------------------------------------------
# ZIP + align + sign
# ---------------------------------------------------------------------------

def make_zip(files: dict[str, bytes]) -> bytes:
    """Create zipaligned APK (4-byte) with STORED entries for alignment-sensitive files."""
    # We'll write manually for alignment control.
    # Local header = 30 + len(name) + extra; data should start at %4==0 for STORED.
    names = sorted(files.keys(), key=lambda n: (n != "AndroidManifest.xml", n != "resources.arsc", n != "classes.dex", n))
    # Actually typical order: manifest, resources, classes, rest
    preferred = ["AndroidManifest.xml", "classes.dex", "resources.arsc"]
    rest = [n for n in files if n not in preferred]
    names = [n for n in preferred if n in files] + sorted(rest)

    out = bytearray()
    central = bytearray()
    for name in names:
        data = files[name]
        name_b = name.encode("utf-8")
        compress = name.endswith(".png") or name.endswith(".xml") and name != "AndroidManifest.xml"
        # Keep dex/arsc/manifest stored (common); compress html/png optionally.
        # Simpler: STORE everything, zipalign 4.
        method = 0
        crc = zlib.crc32(data) & 0xFFFFFFFF
        # extra padding so data offset % 4 == 0
        # offset of data = len(out) + 30 + len(name) + len(extra)
        base = len(out) + 30 + len(name_b)
        padn = (4 - (base % 4)) % 4
        extra = b"\x00" * padn
        dos_time = 0
        dos_date = ((2026 - 1980) << 9) | (9 << 5) | 5
        local = struct.pack(
            "<IHHHHHIIIHH",
            0x04034B50,
            20,  # version needed
            0,  # flags
            method,
            dos_time,
            dos_date,
            crc,
            len(data),
            len(data),
            len(name_b),
            len(extra),
        )
        data_off = len(out)
        out.extend(local)
        out.extend(name_b)
        out.extend(extra)
        out.extend(data)
        central.extend(
            struct.pack(
                "<IHHHHHHIIIHHHHHII",
                0x02014B50,
                20,  # ver made
                20,  # ver need
                0,
                method,
                dos_time,
                dos_date,
                crc,
                len(data),
                len(data),
                len(name_b),
                0,  # extra
                0,  # comment
                0,  # disk
                0,  # int attr
                0,  # ext attr
                data_off,
            )
        )
        central.extend(name_b)

    cd_off = len(out)
    out.extend(central)
    cd_size = len(central)
    eocd = struct.pack(
        "<IHHHHIIH",
        0x06054B50,
        0,
        0,
        len(names),
        len(names),
        cd_size,
        cd_off,
        0,
    )
    out.extend(eocd)
    return bytes(out)


def v1_sign(files: dict[str, bytes], cert, key) -> dict[str, bytes]:
    def digest(b):
        return hashlib.sha256(b).digest()

    # MANIFEST.MF
    mf_lines = ["Manifest-Version: 1.0", "Created-By: ZChat Builder", ""]
    sf_entries = []
    for name in sorted(files):
        if name.startswith("META-INF/"):
            continue
        d = digest(files[name])
        import base64

        b64 = __import__("base64").b64encode(d).decode()
        mf_lines += [f"Name: {name}", f"SHA-256-Digest: {b64}", ""]
    mf = wrap_mf("\r\n".join(mf_lines) + "\r\n")
    files = dict(files)
    files["META-INF/MANIFEST.MF"] = mf

    # CERT.SF
    sf_lines = ["Signature-Version: 1.0", "Created-By: ZChat Builder"]
    sf_lines += ["SHA-256-Digest-Manifest: " + __import__("base64").b64encode(digest(mf)).decode(), ""]
    # per-entry digest of the section in the manifest
    # Parse sections from mf
    text = mf.decode("utf-8")
    parts = text.split("\r\n\r\n")
    for part in parts[1:]:
        if not part.strip():
            continue
        section = part.strip("\r\n") + "\r\n\r\n"
        # find name
        nline = section.split("\r\n")[0]
        sf_lines += [nline, "SHA-256-Digest: " + __import__("base64").b64encode(digest(section.encode("utf-8"))).decode(), ""]
    sf = wrap_mf("\r\n".join(sf_lines) + "\r\n")
    files["META-INF/CERT.SF"] = sf

    opts = [pkcs7.PKCS7Options.DetachedSignature]
    if hasattr(pkcs7.PKCS7Options, "NoAttributes"):
        opts.append(pkcs7.PKCS7Options.NoAttributes)
    rsa_der = (
        pkcs7.PKCS7SignatureBuilder()
        .set_data(sf)
        .add_signer(cert, key, hashes.SHA256())
        .sign(Encoding.DER, opts)
    )
    files["META-INF/CERT.RSA"] = rsa_der
    return files


def wrap_mf(s: str) -> bytes:
    # JAR spec 72-char line wrap
    out = []
    for line in s.split("\r\n"):
        if line == "":
            out.append("")
            continue
        first, rest = True, line
        while rest:
            limit = 70 if not first else 72
            chunk = rest[:limit]
            rest = rest[limit:]
            out.append(chunk if first else " " + chunk)
            first = False
    return "\r\n".join(out).encode("utf-8")


def apk_digest(apk: bytes, cd_off: int, eocd_off: int, cd_offset_in_eocd: int) -> bytes:
    """v2 chunked digest of contents + CD + EOCD (with patched offset)."""

    def chunk_hash(data: bytes) -> bytes:
        CHUNK = 1024 * 1024
        hashes = []
        off = 0
        while off < len(data):
            piece = data[off : off + CHUNK]
            h = hashlib.sha256()
            h.update(b"\xa5")
            h.update(struct.pack("<I", len(piece)))
            h.update(piece)
            hashes.append(h.digest())
            off += CHUNK
        top = hashlib.sha256()
        top.update(b"\x5a")
        top.update(struct.pack("<I", len(hashes)))
        top.update(b"".join(hashes))
        return top.digest()

    contents = apk[:cd_off]
    cd = apk[cd_off:eocd_off]
    eocd = bytearray(apk[eocd_off:])
    struct.pack_into("<I", eocd, 16, cd_offset_in_eocd)
    # Hash as one sequence of chunks across the three parts (spec: contents, then CD, then EOCD as separate? )
    # Actual spec: the APK is split into 1MB chunks over:
    #  1. contents (offset 0 to signing block)
    #  2. central directory
    #  3. EOCD
    # Each of those three ZIP sections is chunked independently then combined?
    # From the spec: "contents of ZIP entries" then CD then EOCD are concatenated for chunking
    # with the signing block omitted. Chunks are 1MB over that concatenation.
    # Implementation in apksig: three separate parts, each chunked, all chunk hashes concatenated.
    chunks = []

    def feed(data):
        CHUNK = 1024 * 1024
        off = 0
        while off < len(data):
            piece = data[off : off + CHUNK]
            h = hashlib.sha256()
            h.update(b"\xa5")
            h.update(struct.pack("<I", len(piece)))
            h.update(piece)
            chunks.append(h.digest())
            off += CHUNK

    feed(contents)
    feed(cd)
    feed(bytes(eocd))
    top = hashlib.sha256()
    top.update(b"\x5a")
    top.update(struct.pack("<I", len(chunks)))
    top.update(b"".join(chunks))
    return top.digest()


def find_eocd(apk: bytes) -> tuple[int, int]:
    # no comment, EOCD is last 22 bytes
    eocd_off = len(apk) - 22
    assert apk[eocd_off : eocd_off + 4] == b"PK\x05\x06"
    cd_off = struct.unpack_from("<I", apk, eocd_off + 16)[0]
    return cd_off, eocd_off


def v2_sign(apk: bytes, cert, key) -> bytes:
    ALG = 0x0103  # RSASSA-PKCS1-v1_5 with SHA-256
    cd_off, eocd_off = find_eocd(apk)
    # We'll insert signing block at cd_off, so new cd offset = cd_off + block_size
    # Need to know block size to compute digest (EOCD patched with new offset).
    # First compute digest with a predicted block size... circular.
    # Standard approach: build signed-data without knowing block size first,
    # because digest uses the *final* CD offset in EOCD which is the start of the signing block
    # i.e. the original cd_off (signing block is inserted AT cd_off, so contents end at cd_off,
    # and EOCD's cd_offset field is set to cd_off which is the start of the signing block).
    #
    # From spec: "offset of CD as if the signing block did not exist"? No:
    # "The offset of the Central Directory is the offset of the APK Signing Block"
    # because the signing block sits immediately before CD. When hashing EOCD,
    # the field is the offset of the signing block (where CD used to start).
    #
    # Wait. After signing:
    # [contents][signing block][CD][EOCD]
    # EOCD.cd_offset = offset of CD = cd_off + len(signing_block)
    # When hashing, EOCD is modified so cd_offset = offset of signing block = original cd_off
    #
    # So digest does NOT depend on signing block size. Great.

    digest = apk_digest(apk, cd_off, eocd_off, cd_off)

    def lp(data: bytes) -> bytes:
        return struct.pack("<I", len(data)) + data

    cert_der = cert.public_bytes(Encoding.DER)
    signed_data = lp(lp(struct.pack("<I", ALG) + lp(digest))) + lp(lp(cert_der)) + lp(b"")

    signature = key.sign(signed_data, padding.PKCS1v15(), hashes.SHA256())
    pub = key.public_key().public_bytes(Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)
    signer = lp(signed_data) + lp(lp(struct.pack("<I", ALG) + lp(signature))) + lp(pub)
    sig_block_value = lp(signer)  # sequence of signers
    # ID-value pair
    pair = struct.pack("<I", 0x7109871A) + sig_block_value
    pair_lp = struct.pack("<Q", len(pair)) + pair
    # block: size + pairs + size + magic
    magic = b"APK Sig Block 42"
    inner = pair_lp
    # size field is size of (pairs + size + magic) = len(inner) + 8 + 16
    size_of_block_without_first_size = len(inner) + 8 + 16
    block = (
        struct.pack("<Q", size_of_block_without_first_size)
        + inner
        + struct.pack("<Q", size_of_block_without_first_size)
        + magic
    )
    new_cd = cd_off + len(block)
    eocd = bytearray(apk[eocd_off:])
    struct.pack_into("<I", eocd, 16, new_cd)
    return apk[:cd_off] + block + apk[cd_off:eocd_off] + bytes(eocd)


def make_cert():
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "ZChat")])
    cert = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(1)
        .not_valid_before(datetime(2024, 1, 1, tzinfo=timezone.utc))
        .not_valid_after(datetime(2045, 1, 1, tzinfo=timezone.utc))
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
        .sign(key, hashes.SHA256())
    )
    return cert, key


def png_to_raw_icon(path: Path) -> bytes:
    return path.read_bytes()


def main():
    html = WEB.read_bytes()
    dex = _build_dex_with_own_methods()
    manifest = build_manifest()
    arsc = (ORIG / "resources.arsc").read_bytes()

    files = {
        "AndroidManifest.xml": manifest,
        "classes.dex": dex,
        "resources.arsc": arsc,
        "assets/index.html": html,
    }
    # icons: reuse original slots, replace with our icon if present
    for folder in [
        "mipmap-mdpi-v4",
        "mipmap-hdpi-v4",
        "mipmap-xhdpi-v4",
        "mipmap-xxhdpi-v4",
        "mipmap-xxxhdpi-v4",
    ]:
        src = ORIG / "res" / folder / "ic_launcher.png"
        files[f"res/{folder}/ic_launcher.png"] = src.read_bytes()

    print("dex", len(dex), "manifest", len(manifest), "html", len(html))
    cert, key = make_cert()
    files = v1_sign(files, cert, key)
    apk = make_zip(files)
    apk = v2_sign(apk, cert, key)
    OUT.write_bytes(apk)
    print("wrote", OUT, "size", len(apk))


if __name__ == "__main__":
    main()
