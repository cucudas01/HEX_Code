def decode(hex_code: str, PC=0x3000, B=0x0000, X=0x0000, memory=None):
    """
    SIC / SIC-XE (Format 3/4) 단일 명령 디코더
    - 입력: 명령어 헥스 문자열 (공백/0x 허용)
    - 출력: 항목 dict (Binary, Opcode(6bit), nixbpe, Flag bit, disp/addr, TA, Register A value)
    """
    # 1) 입력 정규화 및 바이트화
    hx = hex_code.strip().lower().replace("0x", "").replace(" ", "")
    if len(hx) % 2 == 1:
        hx = "0" + hx
    bs = bytes.fromhex(hx)
    nbytes = len(bs)
    instr = int.from_bytes(bs, "big")
    bin_all = format(instr, f"0{nbytes*8}b")

    # 이진 문자열 고정폭 포맷터
    def b(v, n):
        return format(v, f"0{n}b")

    # ---------------- 3바이트: SIC 또는 XE Format 3 ----------------
    if nbytes == 3:
        b1, b2, b3 = bs
        opcode_byte = b1 & 0xFC            # 실제 opcode 바이트(상위 6비트 유효)
        e = (b2 & 0x10) >> 4               # XE라면 e 비트 위치(3바이트에서 e=1은 규칙상 모순)

        # --- SIC (교재 관례: 3바이트에서 e=1이면 SIC로 처리) ---
        if e == 1:
            x = (b2 & 0x80) >> 7           # SIC: 주소 15비트의 최상위가 x
            addr15 = ((b2 & 0x7F) << 8) | b3
            TA = (addr15 + (X if x else 0)) & 0xFFFFF

            # LDA일 때만 Register A 값을 메모리에서 로드(있을 때)
            reg_a = "N/A"
            if opcode_byte == 0x00:        # LDA
                reg_a = f"0x{memory[TA]:X}" if (memory and TA in memory) else "Unknown (메모리 미정의)"

            return {
                "Binary code": bin_all,
                "Opcode": b((opcode_byte >> 2) & 0x3F, 6),            # 표준 6비트 표기
                "nixbpe": "SIC (n/i/b/p/e 없음, x는 주소 상위비트)",
                "Flag bit": "SIC, Direct, Format 3",
                "disp/addr": f"{b(addr15, 15)} (15-bit, 0x{addr15:X})",
                "TA": f"0x{TA:X} (Direct, 15-bit{', Indexed(+X)' if x else ''})",
                "Register A value": reg_a,
            }

        # --- SIC/XE Format 3 ---
        opcode6 = (b1 & 0xFC) >> 2
        n = (b1 & 0x02) >> 1
        i = (b1 & 0x01)
        x = (b2 & 0x80) >> 7
        bb = (b2 & 0x40) >> 6              # b
        p  = (b2 & 0x20) >> 5
        e  = 0
        disp12 = ((b2 & 0x0F) << 8) | b3   # 12-bit displacement

        # TA 계산 (교재 규칙)
        if p == 1:                         # PC-relative (부호확장)
            disp = disp12 - 0x1000 if (disp12 & 0x800) else disp12
            TA = (PC + disp) & 0xFFFFF
            rel_desc = f"PC-relative (PC=0x{PC:X} + disp=0x{disp:X})"
        elif bb == 1:                      # Base-relative
            TA = (B + disp12) & 0xFFFFF
            rel_desc = f"Base-relative (B=0x{B:X} + disp=0x{disp12:X})"
        else:                              # Direct (12-bit)
            TA = disp12
            rel_desc = "Direct (12-bit)"

        if x == 1:                         # 인덱싱
            TA = (TA + X) & 0xFFFFF
            rel_desc += f", Indexed (+X=0x{X:X})"

        # 주소 지정 모드(n,i)
        mode = "Simple" if (n, i) == (1, 1) else "Immediate" if (n, i) == (0, 1) else "Indirect" if (n, i) == (1, 0) else "Invalid(n/i)"
        bits6 = f"{n}{i}{x}{bb}{p}{e}"

        # LDA일 때만 Register A 계산 (즉시 / 메모리)
        reg_a = "N/A"
        if opcode_byte == 0x00:            # LDA
            if (n, i) == (0, 1):           # Immediate
                reg_a = f"0x{disp12:X}"
            else:                          # Simple/Indirect -> 메모리 필요
                reg_a = f"0x{memory[TA]:X}" if (memory and TA in memory) else "Unknown (메모리 미정의)"

        return {
            "Binary code": bin_all,
            "Opcode": b(opcode6, 6),
            "nixbpe": f"{bits6} (n={n} i={i} x={x} b={bb} p={p} e={e})",
            "Flag bit": f"SIC/XE, {mode}, {rel_desc}, Format 3",
            "disp/addr": f"{b(disp12, 12)} (12-bit, 0x{disp12:X})",
            "TA": f"0x{TA:X} ({rel_desc})",
            "Register A value": reg_a,
        }

    # ---------------- 4바이트: SIC/XE Format 4 ----------------
    elif nbytes == 4:
        b1, b2, b3, b4 = bs
        opcode_byte = b1 & 0xFC
        opcode6 = (b1 & 0xFC) >> 2
        n = (b1 & 0x02) >> 1
        i = (b1 & 0x01)
        x = (b2 & 0x80) >> 7
        bb = (b2 & 0x40) >> 6              # b (F4에서는 의미 없음)
        p  = (b2 & 0x20) >> 5              # p (F4에서는 의미 없음)
        e  = (b2 & 0x10) >> 4              # e=1 (20-bit addr)
        addr20 = ((b2 & 0x0F) << 16) | (b3 << 8) | b4

        TA = (addr20 + (X if x else 0)) & 0xFFFFF
        rel_desc = f"Direct (20-bit addr{', Indexed(+X)' if x else ''})"
        mode = "Simple" if (n, i) == (1, 1) else "Immediate" if (n, i) == (0, 1) else "Indirect" if (n, i) == (1, 0) else "Invalid(n/i)"
        bits6 = f"{n}{i}{x}{bb}{p}{e}"

        # LDA일 때만 Register A 계산 (메모리 필요)
        reg_a = "N/A"
        if opcode_byte == 0x00:            # LDA (F4)
            reg_a = f"0x{memory[TA]:X}" if (memory and TA in memory) else "Unknown (메모리 미정의)"

        return {
            "Binary code": bin_all,
            "Opcode": b(opcode6, 6),
            "nixbpe": f"{bits6} (n={n} i={i} x={x} b={bb} p={p} e={e})",
            "Flag bit": f"SIC/XE, {mode}, Direct (20-bit), Format 4",
            "disp/addr": f"{b(addr20, 20)} (20-bit, 0x{addr20:X})",
            "TA": f"0x{TA:X} ({rel_desc})",
            "Register A value": reg_a,
        }

    # 그 외 길이는 지원하지 않음
    else:
        raise ValueError("지원 포맷: 3바이트(Format 3) 또는 4바이트(Format 4)만 가능")

# ---------------- 실행부: 매번 PC/B/X를 입력으로 받음 ----------------
if __name__ == "__main__":
    # 예시 메모리(필요 시 수정/확장): TA가 이 키와 일치하면 값을 반환
    sample_mem = {0x3600: 0x103000}

    hx = input("Hex 입력 : ").strip()
    pc_val = int(input("PC (hex): "), 16)
    b_val  = int(input("B  (hex): "), 16)
    x_val  = int(input("X  (hex): "), 16)

    out = decode(hx, PC=pc_val, B=b_val, X=x_val, memory=sample_mem)

    print("Binary   :", out["Binary code"])
    print("Opcode   :", out["Opcode"])
    print("nixbpe   :", out["nixbpe"])
    print("Flag bit :", out["Flag bit"])
    print("disp/addr:", out["disp/addr"])
    print("Target Address =", out["TA"])
    print("Register A value =", out["Register A value"])
