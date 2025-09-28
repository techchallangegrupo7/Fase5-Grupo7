# Analisador STRIDE para Diagramas (MVP)

Este projeto é um MVP que automatiza a **modelagem de ameaças** a partir de **diagramas de arquitetura**. Ele integra três etapas principais:

1) **Preparação de dataset** (ícones + rótulos YOLO)
2) **Geração de variações sintéticas** e divisão em _train/val/test_
3) **Aplicação do detetor (YOLO) + LLM** para produzir um **Relatório STRIDE** em PDF a partir de um diagrama enviado pela interface web (Flask)

---

## Estrutura do Projeto

```
.
├── 1_gera_label.py                     # Gera rótulos iniciais YOLO a partir dos ícones
├── 2_gera_variacoes.py                 # Cria dataset sintético, variações e data.yaml
├── 3_aux_validacao_qtd_classes_images.py # Relatório de contagem de classes/imagens
├── 4_stride_gemini.py                  # Integra YOLO + LLM para gerar relatório STRIDE
├── app.py                              # Interface web Flask para upload e análise
├── .env                                # Variáveis de ambiente (chaves, configs)
├── dataset/                            # Estrutura esperada para imagens/labels/yolo
├── uploads/                            # Uploads de diagramas pelo usuário
├── outputs/                            # PDFs finais gerados
├── previews/                           # Pré-visualizações/anotações
└── static/, fonts/                     # Recursos estáticos e fontes
```

---

## O que faz cada arquivo `.py`


### `1_gera_label.py`

Lê ícones base em `dataset/images/` e gera rótulos YOLO iniciais (arquivos `.txt`) baseados nos nomes.

### `2_gera_variacoes.py`

Com os rótulos gerados, compõe imagens sintéticas com variações de posição/tamanho/augmentations e exporta dataset estruturado para treinamento YOLO.

### `3_aux_validacao_qtd_classes_images.py`

Conta classes e imagens nos diretórios de labels e gera um relatório .txt de distribuição das classes.

### `4_stride_gemini.py`

Executa detecção com YOLO, monta contexto com componentes, consulta LLM (Gemini/OpenAI) e gera relatório STRIDE completo em PDF com ReportLab.

### `app.py`

Interface Flask que recebe upload de diagramas, executa detecção com YOLO, gera prompt para LLM (Gemini ou OpenAI) e produz relatório STRIDE em PDF.

---

## Arquivo `.env`

Exemplo de variáveis de ambiente:

```dotenv
# Chaves de API
GEMINI_API_KEY=SEU_TOKEN_AQUI
OPENAI_API_KEY=SEU_TOKEN_AQUI

# Modelos a utilizar
GEMINI_MODEL=gemini-flash-latest
OPENAI_MODEL=gpt-4.1-mini

# Pesos YOLO
YOLO_WEIGHTS=./dataset/best.pt

# Configurações do Flask
APP_SECRET_KEY=troque_isto_em_producao

# Hiperparâmetros de inferência
FAST_IMG_MAX_SIDE=1280
YOLO_CONF=0.30
YOLO_MAX_DET=50
MAX_COMPONENTS=25
NMS_IOU=0.95
```

- **GEMINI_API_KEY / OPENAI_API_KEY**: tokens de autenticação das LLMs.
- **YOLO_WEIGHTS**: caminho dos pesos YOLO treinados.
- **APP_SECRET_KEY**: chave secreta do Flask.
- **FAST_IMG_MAX_SIDE, YOLO_CONF, YOLO_MAX_DET, MAX_COMPONENTS, NMS_IOU**: parâmetros de controle da detecção e geração do relatório.

---

## Como rodar

1. Instale dependências:

   ```bash
   pip install flask pillow reportlab ultralytics google-generativeai openai pyyaml scikit-learn
   ```
2. Crie `.env` com suas chaves e configs.
3. Execute:

   ```bash
   python app.py
   ```
4. Acesse `http://localhost:5000`, faça upload de um diagrama e baixe o PDF gerado em `outputs/`.
