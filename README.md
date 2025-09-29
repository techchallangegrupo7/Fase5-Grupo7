# Analisador STRIDE para Diagramas (MVP)

Este projeto é um MVP desenvolvido para o Hackathon FIAP (Fase 5) com foco em **modelagem de ameaças** aplicando o método **STRIDE** em **diagramas de arquitetura**.
Ele une **Visão Computacional (YOLO)** + **LLMs (Gemini/OpenAI)** + **Flask** + **ReportLab**, entregando um **Relatório STRIDE em PDF** automaticamente.

---

## 🎯 Objetivo

- Detectar **componentes** em diagramas de arquitetura.
- Aplicar a metodologia **STRIDE** (Spoofing, Tampering, Repudiation, Information Disclosure, Denial of Service, Elevation of Privilege).
- Gerar **ameaças e mitigações recomendadas** por componente.
- Produzir um **PDF estruturado** com sumário executivo e recomendações.

---

## 📌 Arquitetura Geral

1. **YOLO (Ultralytics)** → detecta ícones/componentes no diagrama.
2. **LLM (Gemini/OpenAI)** → analisa os componentes detectados e gera ameaças STRIDE + mitigação.
3. **ReportLab** → monta o PDF final com título, sumário, ameaças, mitigações e diagrama anotado.
4. **Flask** → expõe uma interface web para upload do diagrama e download do relatório.

---

## ⚡ Fluxo de Uso

1. Preparar dataset de ícones (com scripts `1_gera_label.py` e `2_gera_variacoes.py`).
2. Validar consistência do dataset (`3_aux_validacao_qtd_classes_images.py`).
3. Treinar YOLO com os dados gerados (`FASE5.ipynb`).
4. Subir o Flask (`app.py`).
5. Fazer upload de um diagrama → sistema aplica YOLO → gera relatório STRIDE → retorna PDF.

---

## 📂 Estrutura do Projeto

```
.
├── 1_gera_label.py                       # Geração de rótulos YOLO iniciais
├── 2_gera_variacoes.py                   # Criação de dataset sintético com variações
├── 3_aux_validacao_qtd_classes_images.py # Relatório de distribuição de classes
├── 4_stride_gemini.py                    # Integra YOLO + LLM → gera PDF STRIDE
├── app.py                                # Interface Flask (upload, análise, relatório)
├── FASE5.ipynb                           # Notebook do treinamento YOLO
├── .env                                  # Variáveis de ambiente
├── dataset/                              # Dataset de treino/teste YOLO
│   ├── images/                           # Ícones base
│   ├── labels/                           # Labels YOLO
│   └── yolo_sem_rotacao/                 # train/val/test + data.yaml
├── uploads/                              # Uploads do usuário
├── outputs/                              # Relatórios PDF gerados
├── previews/                             # Pré-visualizações anotadas
└── static/                               # Arquivos estáticos do Flask
```

---

## 📜 Arquivos Python e Notebook

### `1_gera_label.py`

- Lê ícones em `dataset/images/`.
- Normaliza nomes dos arquivos.
- Gera rótulos YOLO iniciais (`.txt`).
- Cria mapeamento `id → classe` para o dataset.

### `2_gera_variacoes.py`

- Usa os ícones rotulados para gerar **dataset sintético**.
- Aplica **augmentations** (zoom, rotação, brilho/contraste).
- Cria **data.yaml** no formato YOLO Ultralytics.
- Divide dataset em `train/val/test` (70/15/15).

### `3_aux_validacao_qtd_classes_images.py`

- Conta classes em diretórios de labels.
- Gera relatório `.txt` com distribuição (ex.: nº de imagens, nº de classes).
- Útil para checar balanceamento do dataset.

### `4_stride_gemini.py`

- Recebe diagrama → roda YOLO → detecta componentes.
- Monta prompt com componentes detectados.
- Chama **LLM** (Gemini ou OpenAI).
- Retorna **ameaças STRIDE + mitigação**.
- Gera PDF com ReportLab, incluindo sumário, análise e diagrama anotado.

### `app.py`

- Sobe o servidor **Flask**.
- Rota `/` → página inicial para upload.
- Rota `/analyze` → processa diagrama, roda YOLO + LLM e gera PDF.
- Rota `/f/<folder>/<filename>` → serve arquivos (PDFs, imagens anotadas).
- Gerencia `uploads/`, `previews/` e `outputs/`.
- Usa `dotenv` para carregar variáveis.

### `FASE5.ipynb`

- Notebook do treinamento utilizando YOLOv8s.
- Gera log do treinamento e salva em arquivo `.txt`.

---

## 🔑 Arquivo `.env`

Exemplo:

```dotenv
# APIs
GEMINI_API_KEY=SEU_TOKEN_AQUI
GEMINI_MODEL=gemini-flash-latest
OPENAI_API_KEY=SEU_TOKEN_AQUI
OPENAI_MODEL=gpt-5-nano

# YOLO
YOLO_WEIGHTS=./dataset/treinamento_yolo_aws_best.pt

# Flask
APP_SECRET_KEY=troque_isto_em_producao

# Configurações de inferência
FAST_IMG_MAX_SIDE=1280
YOLO_CONF=0.30
YOLO_MAX_DET=50
MAX_COMPONENTS=25
NMS_IOU=0.95
```

📌 **Descrição das variáveis**:

- **GEMINI_API_KEY / OPENAI_API_KEY** → chaves de autenticação.
- **GEMINI_MODEL / OPENAI_MODEL** → modelo LLM a ser usado.
- **YOLO_WEIGHTS** → caminho dos pesos YOLO treinados.
- **APP_SECRET_KEY** → chave do Flask.
- **FAST_IMG_MAX_SIDE** → redimensionamento para acelerar processamento.
- **YOLO_CONF / YOLO_MAX_DET / NMS_IOU** → hiperparâmetros do YOLO.
- **MAX_COMPONENTS** → limite de componentes por análise.

---

## 🚀 Como Rodar

1. **Instalar dependências**

   ```bash
   pip install -r requirements.txt
   ```
2. **Criar `.env`**

   - Preencha com suas chaves e configs.
3. **Executar**

   ```bash
   python app.py
   ```
4. **Acessar**

   - Abra [http://localhost:5000](http://localhost:5000).
   - Faça upload de um diagrama.
   - Baixe o relatório em `outputs/`.

---

## 🌐 Endpoints Flask

- `GET /` → página de upload.
- `POST /analyze` → processa diagrama e gera relatório.
- `GET /f/<folder>/<filename>` → baixa arquivos gerados.

---

## ✅ Boas Práticas

- **Nunca versionar `.env`** → mantenha chaves fora do repositório.
- **Fixar versões no `requirements.txt`** → garante reprodutibilidade.
- **Revisar dataset sintético** → balanceamento influencia muito na acurácia.
- **Escolher 1 LLM** (Gemini ou OpenAI) para reduzir complexidade.
- **Monitorar PDFs gerados** → revisar ameaças/mitigações sugeridas pelo LLM.

---

## 📄 Licença / Créditos

Projeto acadêmico para Hackathon FIAP – Fase 5: **Modelagem de Ameaças com IA (STRIDE)**.
