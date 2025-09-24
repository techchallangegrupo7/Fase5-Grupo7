# Analisador STRIDE para Diagramas (YOLO + Gemini + Flask)

Este repositório contém um pipeline completo para **detectar componentes em diagramas de arquitetura** (AWS/Azure), **gerar análises STRIDE** com LLM e **exportar um relatório em PDF A4**, além de uma **interface web** (Flask) para envio de imagens e download do relatório.

## Visão Geral dos Módulos

- `criar_diagramas.py` — Gera **diagramas sintéticos** (AWS/Azure) com o pacote `diagrams` para testes e dataset. Saída em PNG/SVG/JPG.  
- `1_gera_label.py` — Varre `dataset/images`, cria **labels YOLO** em `dataset/labels` (uma caixa por imagem, cobrindo 100%), e gera `dataset/classes.yaml` com o mapa de classes.  
- `2_gera_variacoes.py` — (Augmentation) Gera **variações/augmentations** dos ícones/diagramas.  
- `3_aux_validacao_qtd_classes_images.py` — Faz **contagem/validação** de classes a partir dos `.txt` de labels e exporta um relatório `.txt`.  
- `4_stride_gemini.py` — Pipeline **CLI**: carrega YOLO, detecta componentes em imagens, **anota a imagem**, chama o LLM (Gemini) para **Análise STRIDE** e **Mitigações**, e **gera PDF**.  
- `app.py` — **Aplicação Flask** com upload de diagrama/logo, detecção (YOLO), geração do PDF e **UI dark** com legenda dos componentes.  
- `.env` — Variáveis de ambiente para pesos do YOLO, chave do Gemini, thresholds e branding.

> Observação: para treinar um modelo YOLO, utilize sua rotina preferida. Este projeto consome os pesos prontos configurados em `YOLO_WEIGHTS`.

---

## Requisitos

- **Python 3.10+** recomendado
- **Graphviz (sistema)** instalado e no `PATH` (necessário para `diagrams`):
  - Windows: instale o Graphviz pelo instalador oficial e reinicie o terminal
  - Linux: `sudo apt-get install graphviz`
  - macOS: `brew install graphviz`
- (Opcional) **GPU CUDA**: instalar `torch` com CUDA adequado (veja: https://pytorch.org/get-started/locally/). O app usa CPU se CUDA não estiver disponível.

Instale as dependências Python:

```bash
pip install -r requirements.txt
```

---

## Estrutura de Pastas (sugerida)

```
project/
├─ app.py
├─ 1_gera_label.py
├─ 2_gera_variacoes.py
├─ 3_aux_validacao_qtd_classes_images.py
├─ 4_stride_gemini.py
├─ criar_diagramas.py
├─ .env
├─ weights/
│  └─ best.pt                 # seus pesos YOLO (ou configure YOLO_WEIGHTS no .env)
├─ dataset/
│  ├─ images/                  # PNG/JPG dos ícones/diagramas
│  ├─ labels/                  # TXT no formato YOLO
│  └─ classes.yaml             # gerado pelo 1_gera_label.py
├─ uploads/                    # gerenciado pela app web
├─ previews/                   # imagens anotadas (legenda)
└─ outputs/                    # PDFs gerados
```

---

## Configuração (.env)

Crie/edite o arquivo `.env` na raiz com, por exemplo:

```ini
GEMINI_API_KEY=SEU_TOKEN_AQUI
YOLO_WEIGHTS=./weights/best.pt
APP_SECRET_KEY=um_segredo_qualquer
FAST_IMG_MAX_SIDE=1280
YOLO_CONF=0.25
YOLO_MAX_DET=50
MAX_COMPONENTS=25
NMS_IOU=0.5
```

- `GEMINI_API_KEY`: chave da API do Gemini (se não definida, a app usa **placeholders** para o texto do relatório).
- `YOLO_WEIGHTS`: caminho para os pesos do YOLO (pode ser relativo ou absoluto).
- `FAST_IMG_MAX_SIDE`: redimensiona imagens grandes para acelerar a inferência.
- `YOLO_CONF`: limiar de confiança do YOLO.
- `YOLO_MAX_DET`: máximo de detecções por imagem.
- `MAX_COMPONENTS`: máximo de componentes listados no PDF/HTML (0 = sem limite).
- `NMS_IOU`: limiar de IoU para supressão simples de sobreposição.

---

## Como Usar

### 1) Gerar diagramas sintéticos (opcional)
Gera um conjunto de imagens com serviços AWS/Azure aleatórios, para testes/treino:

```bash
python criar_diagramas.py --n 100 --out diagramas --fmt png
```

Isso cria `diagramas/diagram_0001.png`, etc.

### 2) Criar labels YOLO a partir dos arquivos de `dataset/images`
Se você possui um conjunto de ícones/diagramas em `dataset/images`, gere os rótulos:

```bash
python 1_gera_label.py
```

- Cria/atualiza `dataset/labels/*.txt` e `dataset/classes.yaml`.
- **Regra de classe**: o nome do arquivo (sem sufixo `_dark`/`_light`) define o nome da classe.

### 3) (Opcional) Gerar variações
Para aumentar a diversidade dos dados (augmentations), rode:

```bash
python 2_gera_variacoes.py
```

Ajuste os parâmetros dentro do script conforme sua necessidade.

### 4) Validar/Contar classes nos `.txt`
Verifica os IDs presentes nos rótulos (útil para sanity check/estratificação):

```bash
python 3_aux_validacao_qtd_classes_images.py
```

Cria um `relatorio.txt` com a contagem por diretório/pasta de labels.

### 5) Rodar a análise STRIDE por linha de comando
Analisa uma lista de imagens, gera a imagem **anotada** e um **PDF** por execução:

```bash
python 4_stride_gemini.py
```

- Requer `YOLO_WEIGHTS` no `.env` (ou ajuste no script).
- Se `GEMINI_API_KEY` **não** estiver definido, o texto STRIDE/Mitigações usa **placeholders**.

### 6) Subir a aplicação Web (Flask)
Interface web para enviar um diagrama, visualizar **legenda** e **baixar o PDF**:

```bash
python app.py
```

Depois, acesse: `http://127.0.0.1:5000/`  
Faça upload do **diagrama** (e opcionalmente de um **logo**), ajuste `Título/Subtítulo/Cores`, e clique em **Analisar e gerar PDF**.

---

## Notas de Execução & Dicas

- **Fonts**: a aplicação tenta usar `arial.ttf`; se não disponível, cai no `ImageFont.load_default()`.
- **LLM**: para produção, configure o Gemini no `.env`. Em testes, o **modo rápido** (sem LLM) está disponível na UI.
- **GPU**: se o PyTorch detectar CUDA, a inferência YOLO pode usar half-precision para ganhar velocidade.
- **Graphviz/Diagrams**: necessário para gerar diagramas; em servidores Linux, instale o pacote do sistema e garanta que `dot` está no PATH.
- **Treinamento YOLO**: este projeto espera os pesos já treinados (ex.: `weights/best.pt`). Use sua pipeline de treino favorita.

---

## Licença

Uso acadêmico/educacional (Hackathon/estudos).

