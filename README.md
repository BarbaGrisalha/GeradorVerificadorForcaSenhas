# Gerador e Verificador de Senhas

Projeto iniciante em Python para estudar:

- Entropia de senhas
- Boas práticas de criptografia (geração com `secrets`)
- Expressões regulares (`re`) para detectar padrões fracos

## Requisitos

- Python 3.9+
- `tkinter` é opcional (apenas para GUI)

## Uso rápido (CLI)

No diretório pai (`cibersegurança`):

```bash
python3 GeradorVerificadorForcaSenhas/geraveripass.py generate --length 16
python3 GeradorVerificadorForcaSenhas/geraveripass.py check --password "MinhaSenha123!"
```

Ou dentro da pasta do projeto:

```bash
cd GeradorVerificadorForcaSenhas
python3 geraveripass.py generate --length 16
python3 geraveripass.py check --password "MinhaSenha123!"
```

## GUI

```bash
python3 GeradorVerificadorForcaSenhas/geraveripass.py --gui
```

Se `tkinter` não estiver disponível, o programa mostra instruções de fallback para CLI.

## Executar testes

```bash
cd GeradorVerificadorForcaSenhas
python3 -m unittest -v teste_geraveripass.py
```

## Observações

- A estimativa de quebra é simplificada (força bruta pura).
- Não usa dicionários reais nem ataques híbridos.
- Use como ferramenta educacional.
