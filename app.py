from __future__ import annotations
import os
import time
import traceback
from datetime import datetime
from typing import List, Dict, Tuple

from flask import (
    Flask,
    request,
    render_template_string,
    redirect,
    url_for,
    send_from_directory,
    flash,
)
from werkzeug.utils import secure_filename
from dotenv import load_dotenv

load_dotenv()

# ---------- Imports externos ----------
from PIL import Image, ImageDraw, ImageFont

try:
    from reportlab.lib.pagesizes import A4
    from reportlab.lib.utils import ImageReader
    from reportlab.lib.colors import HexColor
    from reportlab.platypus import (
        SimpleDocTemplate, Paragraph, Spacer, Image as RLImage,
        ListFlowable, ListItem
    )
    from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
    from reportlab.lib.enums import TA_LEFT
except Exception as e:
    raise SystemExit(f"Erro ao importar ReportLab: {e}")

# Torch (opcional) só para detectar GPU e usar half-precision
try:
    import torch
    _HAS_CUDA = torch.cuda.is_available()
    if _HAS_CUDA:
        torch.backends.cudnn.benchmark = True
except Exception:
    _HAS_CUDA = False

# ---------- Configurações ----------
MAX_CONTENT_LENGTH_MB = int(os.getenv("MAX_CONTENT_LENGTH_MB", "15"))
ALLOWED_EXTENSIONS = {"png", "jpg", "jpeg"}

UPLOAD_FOLDER = os.path.abspath("uploads")
PREVIEW_FOLDER = os.path.abspath("previews")
OUTPUT_FOLDER = os.path.abspath("outputs")
FONTS_FOLDER = os.path.abspath("fonts")

# Performance tunável por .env
FAST_IMG_MAX_SIDE = int(os.getenv("FAST_IMG_MAX_SIDE", "1280"))  # downscale do maior lado
YOLO_CONF = float(os.getenv("YOLO_CONF", "0.30"))                 # limiar de confiança
YOLO_MAX_DET = int(os.getenv("YOLO_MAX_DET", "50"))               # máx. detecções
MAX_COMPONENTS = int(os.getenv("MAX_COMPONENTS", "25"))           # máx. componentes no PDF/UI
QUICK_DEFAULT = os.getenv("QUICK_DEFAULT", "0") == "1"            # modo rápido default (sem LLM)

# Gemini / LLM
DISABLE_GEMINI = os.getenv("DISABLE_GEMINI", "0") == "1"
GEMINI_API_KEY = os.getenv("GEMINI_API_KEY")
GEMINI_MODEL = os.getenv("GEMINI_MODEL", "gemini-1.5-flash")

# YOLO
YOLO_WEIGHTS = os.getenv("YOLO_WEIGHTS", os.path.join("weights", "best.pt"))

NMS_IOU = float(os.getenv("NMS_IOU", "0.5"))   # 0.5 padrão; use 0.9–0.99 para manter mais caixas

# ---------- Pastas ----------
os.makedirs(UPLOAD_FOLDER, exist_ok=True)
os.makedirs(PREVIEW_FOLDER, exist_ok=True)
os.makedirs(OUTPUT_FOLDER, exist_ok=True)

# Limpa prévias muito antigas (2 dias)
_now = time.time()
for f in list(os.listdir(PREVIEW_FOLDER)):
    p = os.path.join(PREVIEW_FOLDER, f)
    try:
        if os.path.isfile(p) and _now - os.path.getmtime(p) > 2 * 24 * 3600:
            os.remove(p)
    except Exception:
        pass

# ---------- Flask ----------
app = Flask(__name__)
app.config["MAX_CONTENT_LENGTH"] = MAX_CONTENT_LENGTH_MB * 1024 * 1024
app.config["UPLOAD_FOLDER"] = UPLOAD_FOLDER
app.secret_key = os.getenv("APP_SECRET_KEY", "dev_secret_change_me")

# Modelo YOLO inicializado sob demanda
_YOLO_MODEL = None

# ---------- Gemini ----------
_gemini = None
if not DISABLE_GEMINI:
    try:
        import google.generativeai as genai
        if not GEMINI_API_KEY:
            print("[AVISO] GEMINI_API_KEY não definido. Defina ou use DISABLE_GEMINI=1 para pular LLM.")
            DISABLE_GEMINI = True
        else:
            genai.configure(api_key=GEMINI_API_KEY)
            _gemini = genai.GenerativeModel(GEMINI_MODEL)
    except Exception as e:
        print(f"[AVISO] Falha ao iniciar Gemini: {e}. Usando placeholders.")
        DISABLE_GEMINI = True
        _gemini = None

# ---------- YOLO ----------
def get_yolo():
    """Carrega o modelo YOLO uma única vez e faz warm-up leve."""
    global _YOLO_MODEL
    if _YOLO_MODEL is None:
        try:
            from ultralytics import YOLO
        except Exception as e:
            raise SystemExit(f"Ultralytics não instalado: {e}")
        if not os.path.exists(YOLO_WEIGHTS):
            raise FileNotFoundError(f"Pesos YOLO não encontrados: {YOLO_WEIGHTS}")
        _YOLO_MODEL = YOLO(YOLO_WEIGHTS)
        # warm-up opcional
        try:
            _YOLO_MODEL.predict(
                imgsz=min(FAST_IMG_MAX_SIDE, 640),
                conf=0.10,
                max_det=1,
                verbose=False,
                device=0 if _HAS_CUDA else "cpu",
                half=_HAS_CUDA,
            )
        except Exception:
            pass
    return _YOLO_MODEL

# ---------- Mapeamento de classes ----------
service_map: Dict[str, str] = {
    "AWS-Backup": "AWS Backup",
    "AWS-Category_Compute": "Serviço de Computação AWS (EC2/Fargate)",
    "AWS-Cloud-logo": "Logo da AWS Cloud",
    "AWS-CloudFront": "Amazon CloudFront",
    "AWS-CloudTrail": "AWS CloudTrail",
    "AWS-CloudWatch": "Amazon CloudWatch",
    "AWS-EFS": "Amazon Elastic File System (EFS)",
    "AWS-ElastiCache": "Amazon ElastiCache",
    "AWS-Key-Management-Service": "AWS Key Management Service (KMS)",
    "AWS-Private-subnet": "Sub-rede Privada da AWS",
    "AWS-Private_vpc": "VPC Privada da AWS",
    "AWS-Public-subnet": "Sub-rede Pública da AWS",
    "AWS-RDS": "Amazon RDS",
    "AWS-Region": "Região da AWS",
    "AWS-Res_Elastic-Load-Balancing_Application-Load-Balancer": "Application Load Balancer (ALB)",
    "AWS-Res_Users": "Usuários da AWS",
    "AWS-Scaling-group": "Grupo de Auto Scaling da AWS",
    "AWS-Shield": "AWS Shield",
    "AWS-Simple-Email-Service": "Amazon SES",
    "AWS-WAF": "AWS WAF",
    "Azure_api": "API do Azure",
    "Azure_api_gateway": "Azure API Gateway",
    "Azure_cloud_services": "Azure Cloud Services",
    "Azure_http": "Protocolo HTTP no Azure",
    "Azure_integration-204-Logic-Apps": "Azure Logic Apps",
    "Azure_management-portal": "Portal de Gerenciamento do Azure",
    "Azure_microsoft_entra": "Microsoft Entra ID (Azure AD)",
    "Azure_resource_group": "Grupo de Recursos do Azure",
    "Azure_services": "Serviços do Azure",
    "Azure_users": "Usuários do Azure",
}

# ---------- Helpers ----------
def allowed_file(filename: str) -> bool:
    return "." in filename and filename.rsplit(".", 1)[1].lower() in ALLOWED_EXTENSIONS

def load_font(size=18):
    try:
        return ImageFont.truetype(os.path.join(FONTS_FOLDER, "arial.ttf"), size)
    except Exception:
        try:
            return ImageFont.truetype("arial.ttf", size)
        except Exception:
            return ImageFont.load_default()

def _resize_if_large(path: str, max_side: int) -> str:
    """Reduz imagem muito grande mantendo proporção, para acelerar inferência."""
    try:
        im = Image.open(path).convert("RGB")
        w, h = im.size
        m = max(w, h)
        if m > max_side:
            scale = max_side / float(m)
            im = im.resize((int(w * scale), int(h * scale)), Image.LANCZOS)
            im.save(path, optimize=True, quality=92)
    except Exception:
        pass
    return path

def iou(box1, box2):
    x_min_inter = max(box1[0], box2[0])
    y_min_inter = max(box1[1], box2[1])
    x_max_inter = min(box1[2], box2[2])
    y_max_inter = min(box1[3], box2[3])
    inter_w = max(0, x_max_inter - x_min_inter)
    inter_h = max(0, y_max_inter - y_min_inter)
    inter_area = inter_w * inter_h
    box1_area = (box1[2] - box1[0]) * (box1[3] - box1[1])
    box2_area = (box2[2] - box2[0]) * (box2[3] - box2[1])
    union_area = box1_area + box2_area - inter_area
    return 0 if union_area == 0 else inter_area / union_area

def nms_iou_filter(boxes, class_names_map, iou_threshold=0.5):
    """NMS simples por IoU, priorizando maior confiança."""
    if not hasattr(boxes, "tolist"):
        return []
    sorted_boxes = sorted(boxes.tolist(), key=lambda b: float(b[4]), reverse=True)
    kept = []
    for b in sorted_boxes:
        if any(iou(b[:4], kb[:4]) > iou_threshold for kb in kept):
            continue
        conf = float(b[4])
        cls_id = int(b[5])
        class_name = class_names_map.get(cls_id, str(cls_id))
        kept.append(b + [class_name])
    return kept

def annotate_image(original_path: str, detections: List, color_hex: str = "#0EA5E9"):
    """Desenha caixas e numerações e adiciona legenda abaixo."""
    img = Image.open(original_path).convert("RGB")
    draw = ImageDraw.Draw(img)
    font = load_font(20)
    color = tuple(int(color_hex.strip("#")[i:i+2], 16) for i in (0, 2, 4))

    legend_lines = []
    iter_boxes = detections if MAX_COMPONENTS <= 0 else detections[:MAX_COMPONENTS]
    for i, b in enumerate(iter_boxes, start=1):
        x1, y1, x2, y2, conf, cls_id, class_name = b
        x1, y1, x2, y2 = map(int, [x1, y1, x2, y2])
        draw.rectangle([x1, y1, x2, y2], outline=color, width=3)
        draw.text((x1, max(0, y1 - 24)), str(i), fill=color, font=font)
        legend_lines.append(f"{i}: {class_name} ({conf:.2f})")

    line_h = 26
    extra_h = len(legend_lines) * line_h + 18 if legend_lines else 0
    if extra_h > 0:
        w, h = img.size
        new_img = Image.new("RGB", (w, h + extra_h), (255, 255, 255))
        new_img.paste(img, (0, 0))
        draw2 = ImageDraw.Draw(new_img)
        y = h + 10
        for line in legend_lines:
            draw2.text((16, y), line, fill=(0, 0, 0), font=font)
            y += line_h
        img = new_img

    base = os.path.basename(original_path)
    out_path = os.path.join(PREVIEW_FOLDER, f"labeled_{base}")
    img.save(out_path, optimize=True)
    return out_path, legend_lines

# Cache simples para evitar chamar o LLM repetidas vezes para o mesmo componente
GEMINI_CACHE: Dict[str, Tuple[str, str]] = {}

# --- Parser de texto -> seções STRIDE (bullets por categoria) ---
import re

_STRIDE_CANON = [
    "Spoofing",
    "Tampering",
    "Repudiation",
    "Information Disclosure",
    "Denial of Service",
    "Elevation of Privilege",
]

_STRIDE_ALIASES = {
    "Spoofing": [r"spoofing"],
    "Tampering": [r"tampering", r"manipula(?:ç|c)ão"],
    "Repudiation": [r"repudiation", r"rep(?:ú|u)d[ií]o"],
    "Information Disclosure": [
        r"information\s+disclosure",
        r"divulga(?:ç|c)[aã]o\s+de\s+informa",
        r"info\s*disclosure",
    ],
    "Denial of Service": [
        r"denial\s+of\s+service",
        r"\bdo?s\b",
        r"nega(?:ç|c)[aã]o\s+de\s+servi",
    ],
    "Elevation of Privilege": [
        r"elevation\s+of\s+privilege",
        r"eleva(?:ç|c)[aã]o\s+de\s+privil[eé]gio",
        r"\beop\b",
    ],
}

# cabeçalho "limpo" (linha só com a categoria)
_HEADER_PURE_RE = re.compile(
    r"^\s{0,3}(?:[-*#]+\s*)?(?:\*\*)?\s*(?:[A-Z]\s*-\s*)?(%s)\s*:?\s*(?:\*\*)?\s*$"
    % "|".join(rf"(?:{alias})"
               for aliases in _STRIDE_ALIASES.values() for alias in aliases),
    re.IGNORECASE
)

# cabeçalho inline "Categoria: item já na mesma linha"
_HEADER_INLINE_RE = re.compile(
    r"^\s*(?:\*\*)?\s*(?:[A-Z]\s*-\s*)?(?P<hdr>%s)\s*:\s*(?:\*\*)?\s*(?P<rest>.+?)\s*$"
    % "|".join(rf"(?:{alias})"
               for aliases in _STRIDE_ALIASES.values() for alias in aliases),
    re.IGNORECASE
)

def _canonicalize(header: str) -> str:
    h = header.strip().lower()
    for canon, aliases in _STRIDE_ALIASES.items():
        for a in aliases:
            if re.fullmatch(a, h, flags=re.IGNORECASE):
                return canon
    for canon in _STRIDE_CANON:
        if canon.lower() == h:
            return canon
    return header.strip().title()

def parse_stride_sections(text: str) -> dict[str, list[str]]:
    """
    Converte texto (bullets/headers) em:
      { 'Spoofing': [...], 'Tampering': [...], ... }

    Suporta:
    - "**Spoofing:**" sozinho na linha (cabeçalho puro)
    - "**Spoofing:** implementar ..." (cabeçalho inline + 1º item)
    - Bullets iniciados por '*', '-', '•' ou '1.', '2)'
    - Linhas soltas após um cabeçalho são tratadas como item
    """
    sections = {k: [] for k in _STRIDE_CANON}
    if not text:
        return sections

    current = None
    for raw in text.splitlines():
        line = raw.strip()
        if not line:
            continue

        # 1) Cabeçalho inline (Categoria: item já na mesma linha)
        m_inline = _HEADER_INLINE_RE.match(line.replace("**", "").replace("__", ""))
        if m_inline:
            current = _canonicalize(m_inline.group("hdr"))
            sections.setdefault(current, [])
            first_item = m_inline.group("rest").strip(" -–—:")  # limpa pontuação comum
            if first_item:
                sections[current].append(first_item)
            continue

        # 2) Cabeçalho puro (só a categoria na linha)
        m_pure = _HEADER_PURE_RE.match(line.replace("**", "").replace("__", ""))
        if m_pure:
            current = _canonicalize(m_pure.group(1))
            sections.setdefault(current, [])
            continue

        # 3) Bullet tradicional
        if re.match(r"^(\*|-|•|\d+[\.\)])\s+", line):
            item = re.sub(r"^(\*|-|•|\d+[\.\)])\s+", "", line).strip()
            if current and item:
                sections[current].append(item)
            continue

        # 4) Linha solta → vira item da categoria corrente
        if current:
            sections[current].append(line)

    return sections

def _sanitize_para(s: str) -> str:
    """Converte **bold** em <b> e escapa HTML básico."""
    if not s:
        return ""
    s = re.sub(r"\*\*(.+?)\*\*", r"<b>\1</b>", s)
    s = s.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
    s = s.replace("&lt;b&gt;", "<b>").replace("&lt;/b&gt;", "</b>")
    return s

def sections_to_html(secs: dict[str, list[str]]) -> dict[str, list[str]]:
    return {k: [_sanitize_para(v) for v in (secs.get(k) or [])] for k in _STRIDE_CANON}

# ---------- Gemini ----------
def call_gemini_stride(component_name: str) -> Tuple[str, str]:
    """Retorna (análise, mitigações) via Gemini. Usa cache e placeholders."""
    if component_name in GEMINI_CACHE:
        return GEMINI_CACHE[component_name]

    if DISABLE_GEMINI or _gemini is None:
        analysis = (
            "Spoofing: riscos de identidade falsa.\n"
            "Tampering: alterações não autorizadas.\n"
            "Repudiation: falta de trilhas de auditoria.\n"
            "Information Disclosure: exposição indevida.\n"
            "Denial of Service: indisponibilidade do serviço.\n"
            "Elevation of Privilege: abuso de permissões."
        )
        mitig = (
            "Spoofing: MFA e identidade federada.\n"
            "Tampering: assinaturas, WORM e versionamento.\n"
            "Repudiation: logs imutáveis e trilhas.\n"
            "Info Disclosure: criptografia e DLP.\n"
            "DoS: rate limiting e autoscaling.\n"
            "EoP: princípio do menor privilégio."
        )
        GEMINI_CACHE[component_name] = (analysis, mitig)
        return analysis, mitig

    prompt_a = f"""
    Analise o componente de arquitetura "{component_name}" usando STRIDE.
    Gere somente bullets por categoria (Spoofing, Tampering, Repudiation, Information Disclosure, Denial of Service, Elevation of Privilege).
    Não inclua títulos como 'Análise' ou 'Mitigações'; apenas as listas.
    """
    try:
        resp_a = _gemini.generate_content(prompt_a)
        analysis = resp_a.text
    except Exception as e:
        analysis = f"[Erro ao obter análise do Gemini: {e}]"

    prompt_m = f"""
    Com base nas ameaças a seguir, liste mitigações objetivas (uma por bullet) por categoria STRIDE.
    Não inclua cabeçalhos adicionais: apenas as listas por categoria.
    Ameaças:\n{analysis}
    """
    try:
        resp_m = _gemini.generate_content(prompt_m)
        mitig = resp_m.text
    except Exception as e:
        mitig = f"[Erro ao obter mitigações do Gemini: {e}]"

    GEMINI_CACHE[component_name] = (analysis, mitig)
    return analysis, mitig

# ---------- PDF ----------
def build_pdf_a4(
    pdf_path: str,
    title: str,
    subtitle: str,
    brand_color: str,
    logo_path: str | None,
    source_image_path: str,
    labeled_image_path: str,
    per_component: List[Tuple[str, str, str]],
):
    """Gera PDF A4 com paginação automática e listas/bold."""
    W, H = A4
    try:
        primary = HexColor(brand_color)
    except Exception:
        primary = HexColor("#7C3AED")

    styles = getSampleStyleSheet()
    body = ParagraphStyle(
        "Body", parent=styles["Normal"], fontName="Helvetica",
        fontSize=10, leading=13, alignment=TA_LEFT
    )
    h_comp = ParagraphStyle(
        "Comp", parent=styles["Heading2"], fontName="Helvetica-Bold",
        fontSize=14, textColor=primary, spaceBefore=8, spaceAfter=6
    )
    h_label = ParagraphStyle(
        "Label", parent=styles["Normal"], fontName="Helvetica-Bold",
        fontSize=10, spaceBefore=4, spaceAfter=2
    )

    def _header(canvas, doc):
        canvas.saveState()
        canvas.setFillColor(primary)
        canvas.rect(0, H - 70, W, 70, fill=True, stroke=False)
        if logo_path and os.path.exists(logo_path):
            try:
                canvas.drawImage(ImageReader(logo_path), 24, H - 60, 64, 48, preserveAspectRatio=True, mask='auto')
            except Exception:
                pass
        canvas.setFillColor("white")
        canvas.setFont("Helvetica-Bold", 18)
        canvas.drawString(100, H - 42, title or "Relatório de Ameaças STRIDE")
        canvas.setFont("Helvetica", 11)
        canvas.drawString(100, H - 58, subtitle or "Análise automatizada por YOLO + Gemini")
        canvas.setFillColor("black")
        canvas.setFont("Helvetica", 9)
        canvas.drawString(24, H - 86, f"Gerado em: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        canvas.restoreState()

    doc = SimpleDocTemplate(pdf_path, pagesize=A4, leftMargin=24, rightMargin=24, topMargin=100, bottomMargin=36)
    story = []

    def _image_block(path, caption, max_h):
        if not path or not os.path.exists(path):
            return
        try:
            img = RLImage(path)
            img._restrictSize(doc.width, max_h)
            img.hAlign = "LEFT"
            story.append(img)
            story.append(Spacer(1, 4))
            story.append(Paragraph(f"<b>{caption}</b>", ParagraphStyle("cap", parent=body, fontSize=9)))
            story.append(Spacer(1, 10))
        except Exception:
            pass

    max_img_h = 685
    _image_block(source_image_path, "Figura 1 — Diagrama original", max_img_h)
    _image_block(labeled_image_path, "Figura 2 — Diagrama anotado (detecções)", max_img_h)

    iter_components = per_component if MAX_COMPONENTS <= 0 else per_component[:MAX_COMPONENTS]
    for comp_name, analysis, mitig in iter_components:
        story.append(Paragraph(comp_name, h_comp))

        story.append(Paragraph("Análise STRIDE:", h_label))
        a_sections = parse_stride_sections(analysis)
        has_any = any(a_sections.get(k) for k in _STRIDE_CANON)
        if has_any:
            for cat in _STRIDE_CANON:
                items = a_sections.get(cat) or []
                if not items:
                    continue
                story.append(Paragraph(cat, ParagraphStyle("cat", parent=body, fontName="Helvetica-Bold")))
                story.append(ListFlowable([ListItem(Paragraph(_sanitize_para(i), body), leftIndent=6) for i in items],
                                          bulletType="bullet", start="•", leftIndent=12))
                story.append(Spacer(1, 4))
        else:
            story.append(Paragraph(_sanitize_para(analysis or "—"), body))
        story.append(Spacer(1, 6))

        story.append(Paragraph("Mitigações sugeridas:", h_label))
        m_sections = parse_stride_sections(mitig)
        has_any_m = any(m_sections.get(k) for k in _STRIDE_CANON)
        if has_any_m:
            for cat in _STRIDE_CANON:
                items = m_sections.get(cat) or []
                if not items:
                    continue
                story.append(Paragraph(cat, ParagraphStyle("cat", parent=body, fontName="Helvetica-Bold")))
                story.append(ListFlowable([ListItem(Paragraph(_sanitize_para(i), body), leftIndent=6) for i in items],
                                          bulletType="bullet", start="•", leftIndent=12))
                story.append(Spacer(1, 4))
        else:
            story.append(Paragraph(_sanitize_para(mitig or "—"), body))
        story.append(Spacer(1, 10))

    doc.build(story, onFirstPage=_header, onLaterPages=_header)

# ---------- HTML (Jinja) ----------
BASE_HTML = r"""
<!DOCTYPE html>
<html lang="pt-br">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>{{ page_title or 'Analisador STRIDE para Diagramas - Grupo 7 - 4IADT' }}</title>
  <style>
    :root{ --brand: {{ primary_color }}; --accent: {{ secondary_color }}; }
    /* Dark theme */
    html,body{ height:100%; }
    body{ font-family: system-ui,-apple-system,Segoe UI,Roboto,Arial,sans-serif; margin:0; background:#0B1220; color:#E5E7EB; }
    header{ background: #0D1326; border-bottom:1px solid #111827; color:#fff; padding: 18px 16px; position:sticky; top:0; z-index:10; }
    h1{ margin:0; font-size: 22px; }
    h2{ margin: 16px 0 8px; font-size: 18px; color:#E5E7EB; }
    main{ max-width: 980px; margin: 20px auto; padding: 0 16px; }
    .card{ background:#0F172A; border:1px solid #1F2937; border-radius:16px; padding:16px; box-shadow:0 10px 25px rgba(0,0,0,.35); margin-bottom:16px; }
    .grid{ display:grid; grid-template-columns:1fr 1fr; gap:16px; align-items:end; }
    .btn{ background: var(--brand); color:#0B1220; border:none; padding:10px 16px; border-radius:10px; cursor:pointer; text-decoration:none; font-weight:600; }
    .btn.secondary{ background: var(--accent); color:#0B1220; }
    .tip{ font-size: 12px; color:#9CA3AF; }
    .label{ font-weight:600; margin-bottom:6px; display:block; color:#CBD5E1; }
    input[type="text"], input[type="file"], input[type="color"]{
      width:100%; box-sizing:border-box; height:44px; border:1px solid #374151; border-radius:10px; padding:10px; background:#111827; color:#F9FAFB;
    }
    input[type="file"]{ padding:8px; }
    input[type="color"]{ -webkit-appearance:none; appearance:none; padding:0; cursor:pointer; background:#111827; }
    input[type="color"]::-webkit-color-swatch-wrapper{ padding:4px; border-radius:10px; }
    input[type="color"]::-webkit-color-swatch{ border:none; border-radius:8px; }
    input[type="color"]::-moz-focus-inner{ padding:0; border:0; }
    input[type="color"]::-moz-color-swatch{ border:none; border-radius:8px; padding:0; }
    .preview-img{ max-width:100%; border-radius:12px; border:1px solid #1F2937; }
    footer{ text-align:center; padding:24px; color:#94A3B8; font-size:12px; }
    .brand-bar{ display:flex; align-items:center; gap:12px; }
    .brand-logo{ width:36px; height:36px; object-fit:contain; background:#0B1220; border-radius:8px; padding:4px; border:1px solid #1F2937; }
    .flash{ background:#1F2937; color:#F59E0B; padding:10px 12px; border:1px solid #374151; border-radius:8px; margin-bottom:12px; }
    .legend{ font-size: 14px; background:#0B1220; border:1px solid #1F2937; border-radius:10px; padding:10px; }
    .mono{ font-family: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, 'Liberation Mono', monospace; white-space:pre-wrap; }
    details{ background:#0B1220; border:1px solid #1F2937; border-radius:12px; margin:10px 0; }
    summary{ cursor:pointer; padding:10px 14px; user-select:none; font-weight:700; color:#E5E7EB; }
    details > .content{ padding: 0 14px 12px 14px; }
    ul{ margin:8px 0 12px 22px; }
    li{ margin:6px 0; }
    b{ color:#F3F4F6; }
  </style>
</head>
<body>
  <header>
    <div class="brand-bar">
      {% if brand_logo %}<img src="{{ brand_logo }}" class="brand-logo" alt="logo">{% endif %}
      <div>
        <h1>{{ header_title or 'Analisador STRIDE para Diagramas' }}</h1>
        <div class="tip">{{ header_subtitle or 'Detecte componentes (YOLO), gere análise e exporte PDF A4' }}</div>
      </div>
    </div>
  </header>
  <main>
    {% with messages = get_flashed_messages() %}
      {% if messages %}
        {% for m in messages %}<div class="flash">{{ m }}</div>{% endfor %}
      {% endif %}
    {% endwith %}
    {% block content %}{% endblock %}
  </main>
  <footer>Analisador STRIDE para Diagramas - Grupo 7 - 4IADT • {{ year }}</footer>
</body>
</html>
"""

INDEX_HTML = r"""
{% extends "base.html" %}
{% block content %}
<div class="card">
  <h2>Envie seu diagrama</h2>
  <form method="post" action="{{ url_for('analyze') }}" enctype="multipart/form-data">
    <div class="grid">
      <div>
        <label class="label">Diagrama (PNG/JPG até {{ max_mb }}MB)</label>
        <input type="file" name="diagram" accept="image/png,image/jpeg" required>
        <div class="tip">Dica: exporte do draw.io/diagrams.net/Figma com ~2000–3000px de largura.</div>
      </div>
      <div>
        <label class="label">Logo (opcional)</label>
        <input type="file" name="logo" accept="image/png,image/jpeg">
        <div class="tip">Usado no cabeçalho da página e no PDF.</div>
      </div>
    </div>

    <div class="grid" style="margin-top:12px;">
      <div>
        <label class="label">Título (branding)</label>
        <input type="text" name="title" placeholder="Relatório de Ameaças STRIDE">
      </div>
      <div>
        <label class="label">Subtítulo</label>
        <input type="text" name="subtitle" placeholder="Análise automatizada por YOLO + Gemini">
      </div>
    </div>

    <div class="grid" style="margin-top:12px;">
      <div>
        <label class="label">Cor primária</label>
        <input type="color" name="primary" value="{{ primary_color }}">
      </div>
      <div>
        <label class="label">Cor secundária</label>
        <input type="color" name="secondary" value="{{ secondary_color }}">
      </div>
    </div>

    <div style="margin-top:12px;">
      <label class="label"><input type="checkbox" name="quick" value="1" {% if quick_default %}checked{% endif %}> Modo rápido (pula LLM / usa placeholders)</label>
      <div class="tip">Excelente para testes rápidos; desmarque quando quiser texto completo do LLM.</div>
    </div>

    <div style="margin-top:16px; display:flex; gap:12px; align-items:center;">
      <button class="btn" type="submit">Analisar e gerar PDF</button>
      {% if disable_gemini %}<div class="tip">LLM desabilitado — placeholders ativos. Defina GEMINI_API_KEY para ativar.</div>{% endif %}
    </div>
  </form>
</div>
{% endblock %}
"""

RESULTS_HTML = r"""
{% extends "base.html" %}
{% block content %}
<style>
  .toolbar { display:flex; gap:8px; margin-bottom:16px; flex-wrap:wrap; }
  .btn { background: var(--brand); color:#0B1220; border:none; padding:10px 14px; border-radius:10px; cursor:pointer; text-decoration:none; font-weight:600; }
  .btn.secondary { background: var(--accent); color:#0B1220; }
  .component { background:#0F172A; border:1px solid #1F2937; border-radius:14px; padding:18px; margin-bottom:16px; box-shadow:0 6px 16px rgba(0,0,0,.35); }
  .component h3 { margin:0 0 6px; font-size:18px; color:var(--accent); }
</style>

<div class="card">
  <h2>Resultado</h2>
  <div class="grid">
    <div>
      <div class="label">Diagrama anotado</div>
      <img class="preview-img" src="{{ labeled_url }}" alt="labeled">
      {% if legend and legend|length %}
      <div class="legend" style="margin-top:8px;">
        <div class="label">Legenda</div>
        <ul>
          {% for line in legend %}<li class="mono">{{ line }}</li>{% endfor %}
        </ul>
      </div>
      {% endif %}
    </div>
    <div>
      <div class="label">Relatório</div>
      <p>Arquivo PDF A4 gerado com branding aplicado.</p>
      <a class="btn" href="{{ pdf_url }}" download>Baixar PDF</a>
      <a class="btn secondary" href="{{ url_for('index') }}">Nova análise</a>
      <div class="tip" style="margin-top:10px;">Salvo em: <span class="mono">{{ pdf_path }}</span></div>
    </div>
  </div>
</div>

<div class="card">
  <div class="toolbar">
    <button class="btn" id="expand-all">Expandir tudo</button>
    <button class="btn secondary" id="collapse-all">Recolher tudo</button>
  </div>

  <h2>Componentes detectados</h2>
  {% if components and components|length %}
    {% for c in components %}
      <article class="component" data-comp="{{ c.name }}">
        <h3>{{ loop.index }}. {{ c.name }}</h3>

        <details open>
          <summary>Análise STRIDE</summary>
          <div class="content">
            {% set cats = ["Spoofing","Tampering","Repudiation","Information Disclosure","Denial of Service","Elevation of Privilege"] %}
            {% set ns = namespace(has_struct=false) %}
            {% for cat in cats %}
              {% set items = c.analysis_sections_html.get(cat, []) if c.analysis_sections_html else [] %}
              {% if items and items|length %}
                {% set ns.has_struct = true %}
                <details{% if loop.first %} open{% endif %}>
                  <summary>{{ cat }}</summary>
                  <div class="content">
                    <ul>
                      {% for it in items %}<li>{{ it|safe }}</li>{% endfor %}
                    </ul>
                  </div>
                </details>
              {% endif %}
            {% endfor %}
            {% if not ns.has_struct %}
              <div class="mono">{{ c.analysis_html|safe }}</div>
            {% endif %}
          </div>
        </details>

        <details>
          <summary>Mitigações</summary>
          <div class="content">
            {% set cats = ["Spoofing","Tampering","Repudiation","Information Disclosure","Denial of Service","Elevation of Privilege"] %}
            {% set ns2 = namespace(has_struct=false) %}
            {% for cat in cats %}
              {% set items = c.mitig_sections_html.get(cat, []) if c.mitig_sections_html else [] %}
              {% if items and items|length %}
                {% set ns2.has_struct = true %}
                <details>
                  <summary>{{ cat }}</summary>
                  <div class="content">
                    <ul>
                      {% for it in items %}<li>{{ it|safe }}</li>{% endfor %}
                    </ul>
                  </div>
                </details>
              {% endif %}
            {% endfor %}
            {% if not ns2.has_struct %}
              <div class="mono">{{ c.mitigations_html|safe }}</div>
            {% endif %}
          </div>
        </details>
      </article>
    {% endfor %}
  {% else %}
    <div>Nenhum componente detectado acima do limiar.</div>
  {% endif %}
</div>

<script>
  const allDetails = () => Array.from(document.querySelectorAll('details'));
  document.getElementById('expand-all').addEventListener('click', () => allDetails().forEach(d => d.open = true));
  document.getElementById('collapse-all').addEventListener('click', () => allDetails().forEach(d => d.open = false));
</script>
{% endblock %}
"""

from jinja2 import DictLoader
app.jinja_loader = DictLoader({"base.html": BASE_HTML, "index.html": INDEX_HTML, "results.html": RESULTS_HTML})

# ---------- Rotas ----------
@app.get("/")
def index():
    return render_template_string(
        app.jinja_loader.get_source(app.jinja_env, "index.html")[0],
        page_title="Analisador STRIDE para Diagramas - Grupo 7 - 4IADT",
        primary_color="#7C3AED",   # roxo
        secondary_color="#22D3EE", # ciano
        header_title="Analisador STRIDE para Diagramas - Grupo 7 - 4IADT",
        header_subtitle="Detecta componentes (YOLO), gera análise e exporte PDF A4",
        brand_logo=None,
        max_mb=MAX_CONTENT_LENGTH_MB,
        disable_gemini=DISABLE_GEMINI,
        quick_default=QUICK_DEFAULT,
        year=datetime.now().year,
    )

@app.post("/analyze")
def analyze():
    try:
        if "diagram" not in request.files:
            flash("Selecione um diagrama.")
            return redirect(url_for("index"))
        diagram = request.files["diagram"]
        if diagram.filename == "":
            flash("Arquivo inválido.")
            return redirect(url_for("index"))
        if not allowed_file(diagram.filename):
            flash("Formato não permitido. Use PNG ou JPG.")
            return redirect(url_for("index"))

        title = request.form.get("title", "").strip() or "Relatório de Ameaças STRIDE"
        subtitle = request.form.get("subtitle", "").strip() or "Análise automatizada por YOLO + Gemini"
        primary = request.form.get("primary", "#7C3AED")
        secondary = request.form.get("secondary", "#22D3EE")
        quick = request.form.get("quick", "1" if QUICK_DEFAULT else "0") == "1"

        # Salva diagrama e downscale
        filename = secure_filename(diagram.filename)
        src_path = os.path.join(UPLOAD_FOLDER, f"{int(time.time())}_{filename}")
        diagram.save(src_path)
        src_path = _resize_if_large(src_path, FAST_IMG_MAX_SIDE)

        # Logo (opcional)
        logo_path = None
        if "logo" in request.files and request.files["logo"].filename:
            logo = request.files["logo"]
            if allowed_file(logo.filename):
                logo_filename = secure_filename(logo.filename)
                logo_path = os.path.join(UPLOAD_FOLDER, f"logo_{int(time.time())}_{logo_filename}")
                logo.save(logo_path)

        # YOLO
        model = get_yolo()
        results = model.predict(
            source=src_path,
            conf=max(0.25, YOLO_CONF),
            save=False,
            verbose=False,
            device=0 if _HAS_CUDA else "cpu",
            half=_HAS_CUDA,
            #imgsz=FAST_IMG_MAX_SIDE,
            max_det=YOLO_MAX_DET,
            agnostic_nms=True,
        )
        names_map = getattr(model, "names", {})
        detections = nms_iou_filter(results[0].boxes.data, names_map, iou_threshold=NMS_IOU)

        # Anotação
        labeled_path, legend_lines = annotate_image(src_path, detections, color_hex=primary)

        # Componentes únicos
        components = []
        vistos = set()
        iter_boxes = detections if MAX_COMPONENTS <= 0 else detections[:MAX_COMPONENTS]
        for d in iter_boxes:
            class_name = d[6]
            comp = service_map.get(class_name, class_name)
            if comp in vistos:
                continue
            vistos.add(comp)

            if quick:
                global DISABLE_GEMINI
                prev = DISABLE_GEMINI
                DISABLE_GEMINI = True
                analysis, mitig = call_gemini_stride(comp)
                DISABLE_GEMINI = prev
            else:
                analysis, mitig = call_gemini_stride(comp)

            # Estrutura + HTML seguro para web
            a_secs = parse_stride_sections(analysis)
            m_secs = parse_stride_sections(mitig)
            a_secs_html = sections_to_html(a_secs)
            m_secs_html = sections_to_html(m_secs)

            components.append(
                {
                    "name": comp,
                    "analysis": analysis,
                    "mitigations": mitig,
                    "analysis_sections": a_secs,
                    "mitig_sections": m_secs,
                    "analysis_sections_html": a_secs_html,
                    "mitig_sections_html": m_secs_html,
                    "analysis_html": _sanitize_para(analysis),
                    "mitigations_html": _sanitize_para(mitig),
                }
            )

        # PDF
        ts = datetime.now().strftime("%Y%m%d_%H%M%S")
        pdf_name = f"relatorio_stride_{ts}.pdf"
        pdf_path = os.path.join(OUTPUT_FOLDER, pdf_name)
        build_pdf_a4(
            pdf_path=pdf_path,
            title=title,
            subtitle=subtitle,
            brand_color=primary,
            logo_path=logo_path,
            source_image_path=src_path,
            labeled_image_path=labeled_path,
            per_component=[(c["name"], c["analysis"], c["mitigations"]) for c in components],
        )

        return render_template_string(
            app.jinja_loader.get_source(app.jinja_env, "results.html")[0],
            page_title=title,
            primary_color=primary,
            secondary_color=secondary,
            header_title=title,
            header_subtitle=subtitle,
            brand_logo=(
                url_for("serve_file", folder="uploads", filename=os.path.basename(logo_path))
                if logo_path else None
            ),
            labeled_url=url_for("serve_file", folder="previews", filename=os.path.basename(labeled_path)),
            legend=legend_lines,
            components=components,
            pdf_url=url_for("serve_file", folder="outputs", filename=pdf_name),
            pdf_path=pdf_path,
            year=datetime.now().year,
        )
    except Exception as e:
        traceback.print_exc()
        flash(f"Erro ao processar: {e}")
        return redirect(url_for("index"))

@app.get("/f/<path:folder>/<path:filename>")
def serve_file(folder: str, filename: str):
    if folder == "uploads":
        return send_from_directory(UPLOAD_FOLDER, filename, as_attachment=False)
    if folder == "previews":
        return send_from_directory(PREVIEW_FOLDER, filename, as_attachment=False)
    if folder == "outputs":
        return send_from_directory(OUTPUT_FOLDER, filename, as_attachment=True)
    return "Not found", 404

# Dockerfile opcional
DOCKERFILE_TEMPLATE = r"""
FROM python:3.11-slim
WORKDIR /app
ENV PIP_NO_CACHE_DIR=1
RUN apt-get update && apt-get install -y build-essential libjpeg62-turbo-dev zlib1g-dev && rm -rf /var/lib/apt/lists/*
COPY . /app
RUN pip install --no-cache-dir flask==3.0.3 google-generativeai==0.7.2 ultralytics==8.2.103 pillow==10.4.0 reportlab==4.2.2 python-dotenv==1.0.1 werkzeug==3.0.3
ENV GEMINI_API_KEY=""
ENV YOLO_WEIGHTS=/app/weights/best.pt
ENV APP_SECRET_KEY=change_me
EXPOSE 5000
CMD ["python", "app.py"]
"""

if __name__ == "__main__":
    import ssl, os

    # aponte para seus arquivos
    cert_path = os.getenv("SSL_CERT", "cert.pem")   # ou cert.pem
    key_path  = os.getenv("SSL_KEY",  "key.pem")     # ou key.pem

    ssl_ctx = None
    if os.path.exists(cert_path) and os.path.exists(key_path):
        ssl_ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        # (opcional) exigir TLS 1.2+
        try:
            ssl_ctx.minimum_version = ssl.TLSVersion.TLSv1_2
        except Exception:
            pass
        ssl_ctx.load_cert_chain(certfile=cert_path, keyfile=key_path)

    app.run(host="0.0.0.0", port=5000, debug=True, ssl_context=ssl_ctx)
    # app.run(host="0.0.0.0", port=5000, debug=True)
