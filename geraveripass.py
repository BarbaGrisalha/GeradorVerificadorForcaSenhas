#!/usr/bin/env python3
"""
Gerador e verificador de força de senhas (nível iniciante).

Funcionalidades:
- Gerar senhas fortes (maiúsculas/minúsculas, dígitos, símbolos)
- Avaliar força (fraca/média/forte) com base em comprimento, categorias e padrões comuns
- Estimar tempo para quebra por força bruta (cálculos simples)

Uso (CLI):
  python geraveripass.py generate --length 16
  python geraveripass.py check --password "Minha$enha123"

Opção GUI: execute sem argumentos ou use `--gui` (tkinter é opcional).
"""

from __future__ import annotations
import secrets
import string
import re
import math
import argparse
import sys
from typing import Dict, Tuple

try:
    import tkinter as tk
    from tkinter import ttk
    HAS_TK = True
    TK_ERROR = None
except Exception as e:
    HAS_TK = False
    TK_ERROR = f'Falha ao carregar tkinter/ttk: {str(e)}'
    tk = None
    ttk = None


def generate_password(length: int = 16, upper: bool = True, lower: bool = True,
                      digits: bool = True, symbols: bool = True) -> str:
    if length < 1:
        raise ValueError("O comprimento deve ser >= 1")

    pools = []
    if lower:
        pools.append(string.ascii_lowercase)
    if upper:
        pools.append(string.ascii_uppercase)
    if digits:
        pools.append(string.digits)
    if symbols:
        pools.append(string.punctuation)

    if not pools:
        raise ValueError("Ao menos um conjunto de caracteres deve ser ativado")

    # Garantir pelo menos um caractere de cada grupo selecionado
    password_chars = [secrets.choice(pool) for pool in pools]

    all_chars = ''.join(pools)
    for _ in range(length - len(password_chars)):
        password_chars.append(secrets.choice(all_chars))

    # Embaralhar usando SystemRandom
    import random
    random.SystemRandom().shuffle(password_chars)
    return ''.join(password_chars)


def _pool_size_for_password(password: str) -> int:
    size = 0
    if re.search(r'[a-z]', password):
        size += 26
    if re.search(r'[A-Z]', password):
        size += 26
    if re.search(r'\d', password):
        size += 10
    if re.search(r'[^A-Za-z0-9]', password):
        # approximate printable punctuation
        size += len(string.punctuation)
    return size


def estimate_entropy_bits(password: str) -> float:
    pool = _pool_size_for_password(password)
    if pool <= 0:
        return 0.0
    return len(password) * math.log2(pool)


def _has_common_patterns(password: str) -> Tuple[bool, list]:
    patterns_found = []
    pwd = password.lower()
    common = ['password', '1234', '12345', 'qwerty', 'admin', 'letmein']
    for c in common:
        if c in pwd:
            patterns_found.append(c)

    # sequential digits or letters of length >=4
    if re.search(r'(?:0123|1234|2345|3456|4567|5678|6789)', pwd) or re.search(r'(abcd|bcde|cdef|defg)', pwd):
        patterns_found.append('sequencia')

    # repeated chars
    if re.search(r'(.)\1{3,}', password):
        patterns_found.append('repeticao')

    return (len(patterns_found) > 0), patterns_found


def evaluate_strength(password: str) -> Dict[str, object]:
    entropy = estimate_entropy_bits(password)
    has_pattern, patterns = _has_common_patterns(password)

    # Ajuste simples quando padrões óbvios aparecem
    if has_pattern:
        entropy -= 10

    if entropy < 28:
        label = 'Fraca'
    elif entropy < 50:
        label = 'Média'
    else:
        label = 'Forte'

    return {
        'password': password,
        'entropy_bits': max(0.0, entropy),
        'label': label,
        'patterns': patterns,
    }


def _human_time_from_log10_seconds(log10_seconds: float) -> str:
    # Se o tempo em segundos for pequeno, converta diretamente
    if log10_seconds < 6:
        seconds = 10 ** log10_seconds
        if seconds < 60:
            return f"{seconds:.2f} segundos"
        minutes = seconds / 60
        if minutes < 60:
            return f"{minutes:.2f} minutos"
        hours = minutes / 60
        if hours < 24:
            return f"{hours:.2f} horas"
        days = hours / 24
        if days < 365:
            return f"{days:.2f} dias"
        years = days / 365
        return f"{years:.2f} anos"

    # Caso muito grande, trabalhar com ordens de magnitude
    seconds_per_year = 3600 * 24 * 365
    log10_spy = math.log10(seconds_per_year)
    log10_years = log10_seconds - log10_spy
    if log10_years < 6:
        years = 10 ** log10_years
        return f"{years:.2f} anos"
    return f"≈10^{int(math.floor(log10_years))} anos"


def estimate_crack_time(password: str, guesses_per_second: float = 1e9) -> Dict[str, object]:
    pool = _pool_size_for_password(password)
    if pool <= 0:
        return {'guesses': 0, 'seconds': 0, 'readable': '0 segundos'}

    # Número de combinações = pool ** length -> trabalhar em log10 para evitar overflow
    log10_possibilities = len(password) * math.log10(pool)
    log10_gps = math.log10(guesses_per_second)
    log10_seconds = log10_possibilities - log10_gps

    readable = _human_time_from_log10_seconds(log10_seconds)
    return {
        'log10_possibilities': log10_possibilities,
        'log10_seconds': log10_seconds,
        'readable': readable,
    }


def run_cli(argv=None):
    parser = argparse.ArgumentParser(description='Gerador e verificador de força de senhas')
    sub = parser.add_subparsers(dest='cmd')

    g = sub.add_parser('generate', help='Gerar uma senha')
    g.add_argument('--length', '-l', type=int, default=16)
    g.add_argument('--no-upper', action='store_true')
    g.add_argument('--no-lower', action='store_true')
    g.add_argument('--no-digits', action='store_true')
    g.add_argument('--no-symbols', action='store_true')

    c = sub.add_parser('check', help='Avaliar uma senha')
    c.add_argument('--password', '-p', required=True)
    c.add_argument('--gps', type=float, default=1e9, help='Tentativas por segundo (padrão: 1e9)')

    parser.add_argument('--gui', action='store_true', help='Abrir interface gráfica (se disponível)')

    args = parser.parse_args(argv)

    if args.gui:
        if HAS_TK:
            return run_gui()
        print('GUI indisponível neste Python.')
        if TK_ERROR:
            print(f'Motivo: {TK_ERROR}')
        print('Use o modo CLI:')
        print('  python geraveripass.py generate --length 16')
        print('  python geraveripass.py check --password "MinhaSenha123!"')
        return 0

    if args.cmd is None:
        if HAS_TK:
            return run_gui()
        print('GUI indisponível neste Python. Execute um subcomando CLI:')
        print('  python geraveripass.py generate --length 16')
        print('  python geraveripass.py check --password "MinhaSenha123!"')
        print('  python geraveripass.py --help')
        return 0

    if args.cmd == 'generate':
        pwd = generate_password(
            length=args.length,
            upper=not args.no_upper,
            lower=not args.no_lower,
            digits=not args.no_digits,
            symbols=not args.no_symbols,
        )
        print(pwd)
        return 0

    if args.cmd == 'check':
        res = evaluate_strength(args.password)
        crack = estimate_crack_time(args.password, guesses_per_second=args.gps)
        print(f"Senha: {res['password']}")
        print(f"Força: {res['label']}")
        print(f"Entropia aproximada: {res['entropy_bits']:.2f} bits")
        if res['patterns']:
            print('Padrões detectados:', ', '.join(res['patterns']))
        print('Estimativa para quebra (força bruta):', crack['readable'])
        return 0

    parser.print_help()
    return 1


def run_gui():
    root = tk.Tk()
    root.title('Gerador/Verificador de Senhas')

    frm = ttk.Frame(root, padding=12)
    frm.grid()

    # Password entry
    ttk.Label(frm, text='Senha:').grid(column=0, row=0, sticky='w')
    pwd_var = tk.StringVar()
    entry = ttk.Entry(frm, width=40, textvariable=pwd_var)
    entry.grid(column=1, row=0, columnspan=3, sticky='w')

    # Options: length slider and checkboxes
    ttk.Label(frm, text='Comprimento:').grid(column=0, row=1, sticky='w')
    length_var = tk.IntVar(value=16)
    length_scale = ttk.Scale(frm, from_=4, to=64, orient='horizontal', variable=length_var)
    length_scale.grid(column=1, row=1, columnspan=3, sticky='we')

    upper_var = tk.BooleanVar(value=True)
    lower_var = tk.BooleanVar(value=True)
    digits_var = tk.BooleanVar(value=True)
    symbols_var = tk.BooleanVar(value=True)

    ttk.Checkbutton(frm, text='Maiúsculas', variable=upper_var).grid(column=0, row=2, sticky='w')
    ttk.Checkbutton(frm, text='Minúsculas', variable=lower_var).grid(column=1, row=2, sticky='w')
    ttk.Checkbutton(frm, text='Dígitos', variable=digits_var).grid(column=2, row=2, sticky='w')
    ttk.Checkbutton(frm, text='Símbolos', variable=symbols_var).grid(column=3, row=2, sticky='w')

    # Strength indicator
    strength_var = tk.StringVar(value='Força: —')
    strength_lbl = ttk.Label(frm, textvariable=strength_var, font=('TkDefaultFont', 10, 'bold'))
    strength_lbl.grid(column=0, row=3, columnspan=2, sticky='w')

    entropy_var = tk.StringVar(value='Entropia: —')
    ttk.Label(frm, textvariable=entropy_var).grid(column=2, row=3, columnspan=2, sticky='w')

    # Estimated crack time
    crack_var = tk.StringVar(value='Estimativa: —')
    ttk.Label(frm, textvariable=crack_var, wraplength=400).grid(column=0, row=4, columnspan=4, sticky='w')

    # Buttons
    def on_generate():
        pwd = generate_password(
            length=max(4, int(length_var.get())),
            upper=upper_var.get(),
            lower=lower_var.get(),
            digits=digits_var.get(),
            symbols=symbols_var.get(),
        )
        pwd_var.set(pwd)
        on_check()

    def on_check():
        pwd = pwd_var.get()
        if not pwd:
            strength_var.set('Força: —')
            entropy_var.set('Entropia: —')
            crack_var.set('Estimativa: —')
            return
        res = evaluate_strength(pwd)
        crack = estimate_crack_time(pwd)
        strength_var.set(f"Força: {res['label']}")
        entropy_var.set(f"Entropia: {res['entropy_bits']:.1f} bits")
        crack_var.set(f"Estimativa quebra: {crack['readable']}")

        # Color indicator
        lbl = res['label']
        if lbl == 'Fraca':
            color = '#d9534f'  # red
        elif lbl == 'Média':
            color = '#f0ad4e'  # orange
        else:
            color = '#5cb85c'  # green
        strength_lbl.configure(foreground=color)

    def on_copy():
        pwd = pwd_var.get()
        if not pwd:
            return
        root.clipboard_clear()
        root.clipboard_append(pwd)

    btn_generate = ttk.Button(frm, text='Gerar', command=on_generate)
    btn_generate.grid(column=0, row=5, sticky='w')

    btn_check = ttk.Button(frm, text='Avaliar', command=on_check)
    btn_check.grid(column=1, row=5, sticky='w')

    btn_copy = ttk.Button(frm, text='Copiar', command=on_copy)
    btn_copy.grid(column=2, row=5, sticky='w')

    btn_close = ttk.Button(frm, text='Fechar', command=root.destroy)
    btn_close.grid(column=3, row=5, sticky='e')

    # initial focus
    entry.focus()
    root.mainloop()


if __name__ == '__main__':
    sys.exit(run_cli())
