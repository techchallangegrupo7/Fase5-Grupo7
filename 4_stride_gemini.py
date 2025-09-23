import os
import google.generativeai as genai
from PIL import Image, ImageDraw, ImageFont
from ultralytics import YOLO
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Image as RLImage
from reportlab.lib.styles import getSampleStyleSheet
import numpy as np

# ======================
# 1. Mapeamento e Configuração
# ======================

# Dicionário para mapear nomes de classes para nomes de serviços completos.
# Isso garante que o Gemini receba prompts claros e precisos.
service_map = {
    'AWS-Backup': 'AWS Backup',
    'AWS-Category_Compute': 'Serviço de Computação AWS (como EC2 ou Fargate)',
    'AWS-Cloud-logo': 'Logo da AWS Cloud',
    'AWS-CloudFront': 'Amazon CloudFront',
    'AWS-CloudTrail': 'AWS CloudTrail',
    'AWS-CloudWatch': 'Amazon CloudWatch',
    'AWS-EFS': 'Amazon Elastic File System (EFS)',
    'AWS-ElastiCache': 'Amazon ElastiCache',
    'AWS-Key-Management-Service': 'AWS Key Management Service (KMS)',
    'AWS-Private-subnet': 'Sub-rede Privada da AWS',
    'AWS-Private_vpc': 'VPC Privada da AWS',
    'AWS-Public-subnet': 'Sub-rede Pública da AWS',
    'AWS-RDS': 'Amazon Relational Database Service (RDS)',
    'AWS-Region': 'Região da AWS',
    'AWS-Res_Elastic-Load-Balancing_Application-Load-Balancer': 'Application Load Balancer (ALB)',
    'AWS-Res_Users': 'Usuários da AWS',
    'AWS-Scaling-group': 'Grupo de Auto Scaling da AWS',
    'AWS-Shield': 'AWS Shield',
    'AWS-Simple-Email-Service': 'Amazon Simple Email Service (SES)',
    'AWS-WAF': 'AWS Web Application Firewall (WAF)',
    'Azure_api': 'API do Azure',
    'Azure_api_gateway': 'Azure API Gateway',
    'Azure_cloud_services': 'Azure Cloud Services',
    'Azure_http': 'Protocolo HTTP no Azure',
    'Azure_integration-204-Logic-Apps': 'Azure Logic Apps',
    'Azure_management-portal': 'Portal de Gerenciamento do Azure',
    'Azure_microsoft_entra': 'Microsoft Entra ID (antigo Azure Active Directory)',
    'Azure_resource_group': 'Grupo de Recursos do Azure',
    'Azure_services': 'Serviços do Azure',
    'Azure_users': 'Usuários do Azure'
}

# Configuração da API do Gemini
try:
# Configure sua chave de API aqui
    genai.configure(api_key="COLOQUE SUA CHAVE")
    model_gemini = genai.GenerativeModel('gemini-1.5-flash')
except Exception as e:
    print(f"❌ Erro ao configurar a API do Gemini: {e}")
    exit()

# ======================
# 2. Funções de Suporte (YOLO)
# ======================
def calcular_iou(box1, box2):
    x_min_inter = max(box1[0], box2[0])
    y_min_inter = max(box1[1], box2[1])
    x_max_inter = min(box1[2], box2[2])
    y_max_inter = min(box1[3], box2[3])
    inter_width = max(0, x_max_inter - x_min_inter)
    inter_height = max(0, y_max_inter - y_min_inter)
    intersection_area = inter_width * inter_height
    box1_area = (box1[2] - box1[0]) * (box1[3] - box1[1])
    box2_area = (box2[2] - box2[0]) * (box2[3] - box2[1])
    union_area = box1_area + box2_area - intersection_area
    return 0 if union_area == 0 else intersection_area / union_area

def filtrar_deteccoes_por_iou(boxes, names_map, iou_threshold=0.5):
    sorted_boxes = sorted(boxes.tolist(), key=lambda b: float(b[4]), reverse=True)
    filtradas = []
    for box in sorted_boxes:
        is_overlapping = False
        for f_box in filtradas:
            if calcular_iou(box[:4], f_box[:4]) > iou_threshold:
                is_overlapping = True
                break
        if not is_overlapping:
            conf = float(box[4])
            cls_id = int(box[5])
            class_name = names_map[cls_id]
            filtradas.append(box + [class_name])
    return filtradas

# =unda
# 3. Carregamento de Modelos e Dados
# ======================
model_path = r"D:\_fiap\treinamentoModeloYolo\dataset\best.pt"
try:
    model_yolo = YOLO(model_path)
except Exception as e:
    print(f"❌ Erro ao carregar modelo YOLO: {e}")
    exit()

image_paths = [
    r"D:\_fiap\treinamentoModeloYolo\Arquiteturas Imagens\arch_azure.png",
    r"D:\_fiap\treinamentoModeloYolo\Arquiteturas Imagens\arch_aws.png"
]
try:
    font = ImageFont.truetype("arial.ttf", 20)
except IOError:
    font = ImageFont.load_default()
names_map = model_yolo.names

# ======================
# 4. Processamento e Geração de Relatório
# ======================
OUTPUT_FOLDER = "analise_stride"
if not os.path.exists(OUTPUT_FOLDER):
    os.makedirs(OUTPUT_FOLDER)
    print(f"✅ Pasta '{OUTPUT_FOLDER}' criada para salvar os relatórios.")

markdown_report = "# Relatório de Ameaças STRIDE\n\n"
report_story = []
styles = getSampleStyleSheet()

for image_path in image_paths:
    if not os.path.exists(image_path):
        print(f"⚠️ Arquivo não encontrado: {image_path}")
        continue
    
    base_filename = os.path.basename(image_path)
    labeled_image_path = os.path.join(OUTPUT_FOLDER, f"labeled_{base_filename}")
    
    # Processa a imagem com YOLO
    results = model_yolo.predict(source=image_path, conf=0.25, save=False, verbose=False)
    img = Image.open(image_path).convert("RGB")
    draw = ImageDraw.Draw(img)
    deteccoes = filtrar_deteccoes_por_iou(results[0].boxes.data, names_map)
    legend_text = []

    for i, box_info in enumerate(deteccoes, start=1):
        x1, y1, x2, y2, conf, cls_id, class_name = box_info
        x1, y1, x2, y2 = map(int, [x1, y1, x2, y2])
        draw.rectangle([x1, y1, x2, y2], outline="red", width=2)
        draw.text((x1, max(0, y1 - 25)), str(i), fill="red", font=font)
        legend_text.append(f"{i}: {class_name} ({conf:.2f})")

    # Adiciona a legenda e salva a imagem anotada
    line_height = 30
    extra_height = len(legend_text) * line_height + 20
    img_width, img_height = img.size
    new_img = Image.new("RGB", (img_width, img_height + extra_height), (255, 255, 255))
    new_img.paste(img, (0, 0))
    draw_new = ImageDraw.Draw(new_img)
    y_offset = img_height + 10
    for text in legend_text:
        draw_new.text((20, y_offset), text, fill="black", font=font)
        y_offset += line_height
    new_img.save(labeled_image_path)
    print(f"✅ Imagem processada e salva em: {labeled_image_path}")

    # Adiciona a imagem ao relatório
    markdown_report += f"## Relatório para: `{base_filename}`\n\n---\n\n"
    report_story.append(Paragraph(f"## Relatório para: {base_filename}", styles['h2']))
    report_story.append(Spacer(1, 12))
    report_story.append(RLImage(labeled_image_path, width=400, height=300))
    report_story.append(Spacer(1, 12))

    # Análise de ameaças com o Gemini
    for i, box_info in enumerate(deteccoes, start=1):
        class_name = box_info[6]
        
        # Usa o mapeamento para obter o nome do serviço completo para o prompt.
        component_name = service_map.get(class_name, class_name)
        
        print(f"Buscando análise STRIDE para {component_name}...")

        # Prompt para análise de ameaças
        prompt_stride = f"""
        Analise o componente de arquitetura {component_name} usando o modelo de ameaças STRIDE.
        Para cada categoria do STRIDE (Spoofing, Tampering, Repudiation, Information Disclosure, Denial of Service e Elevation of Privilege), identifique as possíveis ameaças e vulnerabilidades específicas desse componente.
        Formate a resposta como uma lista, com a categoria do STRIDE como título.
        """
        try:
            response_gemini = model_gemini.generate_content(prompt_stride)
            stride_analysis = response_gemini.text
            print(f"✅ Análise STRIDE para {component_name} recebida.")
        except Exception as e:
            stride_analysis = f"Erro ao obter análise do Gemini: {e}"
            print(f"❌ Erro para {component_name}: {e}")

        # Adiciona a análise ao relatório
        markdown_report += f"### {i}: {component_name}\n"
        markdown_report += f"#### Análise STRIDE\n{stride_analysis}\n\n"
        report_story.append(Paragraph(f"### {i}: {component_name}", styles['h3']))
        report_story.append(Spacer(1, 6))
        report_story.append(Paragraph("<b>Análise STRIDE:</b>", styles['Normal']))
        report_story.append(Paragraph(stride_analysis.replace('\n', '<br/>'), styles['Normal']))
        report_story.append(Spacer(1, 12))

        # Prompt para mitigações
        print(f"Buscando mitigações para {component_name}...")
        prompt_mitigacoes = f"""
        Com base nas seguintes ameaças de segurança identificadas:
        {stride_analysis}
        Forneça direcionamentos e boas práticas para mitigar cada uma delas. Liste as mitigações de forma clara e objetiva para cada categoria de ameaça (Spoofing, Tampering, etc.).
        """
        try:
            response_mitigacoes = model_gemini.generate_content(prompt_mitigacoes)
            mitigations = response_mitigacoes.text
            print(f"✅ Mitigações para {component_name} recebidas.")
        except Exception as e:
            mitigations = f"Erro ao obter mitigações do Gemini: {e}"
            print(f"❌ Erro para {component_name}: {e}")
        
        # Adiciona as mitigações ao relatório
        markdown_report += f"#### Mitigações Sugeridas\n{mitigations}\n\n"
        report_story.append(Paragraph("<b>Mitigações Sugeridas:</b>", styles['Normal']))
        report_story.append(Paragraph(mitigations.replace('\n', '<br/>'), styles['Normal']))
        report_story.append(Spacer(1, 12))
        
    markdown_report += "---\n\n"
    report_story.append(Spacer(1, 24))

# ======================
# 5. Salvar Relatórios
# ======================
markdown_output_path = os.path.join(OUTPUT_FOLDER, "relatorio_stride.md")
pdf_output_path = os.path.join(OUTPUT_FOLDER, "relatorio_stride.pdf")

with open(markdown_output_path, "w", encoding="utf-8") as f:
    f.write(markdown_report)

doc = SimpleDocTemplate(pdf_output_path)
doc.build(report_story)

print(f"📄 Relatórios gerados em '{OUTPUT_FOLDER}': {os.path.basename(markdown_output_path)} e {os.path.basename(pdf_output_path)}")