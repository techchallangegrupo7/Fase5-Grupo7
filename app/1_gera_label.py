import os
import cv2
import re

# --- Caminhos ---
images_path = "dataset"
labels_path = "dataset"
os.makedirs(labels_path, exist_ok=True)

# --- 1️⃣ Encontrar e preparar a lista de arquivos ---
all_png_files = []
# Percorre todas as pastas e subpastas para encontrar os arquivos .png
for dirpath, dirnames, filenames in os.walk(images_path):
    for filename in filenames:
        if filename.lower().endswith('.png'):
            all_png_files.append(os.path.join(dirpath, filename))

# --- 2️⃣ Criar class_map com a lógica de nome base ---
# Pegar nomes base únicos de todos os arquivos, usando rsplit
class_names = set()
for full_path in all_png_files:
    filename = os.path.basename(full_path)
    
    # --- Nova lógica para determinar o nome base ---
    filename_without_ext = os.path.splitext(filename)[0]
    
    # Pega a parte após o último '_'
    partes = filename_without_ext.rsplit('_', 1)
    
    # Verifica se a última parte contém algum dígito (número)
    if len(partes) > 1 and re.search(r'\d', partes[-1]):
        # Se contiver, a última parte é a versão, e o nome base é a parte anterior
        base_name = partes[0]
    else:
        # Se não contiver (ex: 'aws_cd_special'), retira o último segmento
        # para chegar ao nome base correto
        base_name = filename_without_ext.rsplit('_', 2)[0]
        
    class_names.add(base_name)

# Ordena os nomes para garantir que os IDs sejam consistentes
class_names = sorted(list(class_names))

# Gera ID único para cada classe
class_map = {name: idx for idx, name in enumerate(class_names)}

print("Classes detectadas:")
for name, idx in class_map.items():
    print(f"{idx}: {name}")

# --- 3️⃣ Gerar labels YOLO ---
for full_path in all_png_files:
    # Obtém o nome do arquivo e o diretório
    dir_name, filename = os.path.split(full_path)
    
    # --- Aplica a mesma lógica de nome base para o arquivo atual ---
    filename_without_ext = os.path.splitext(filename)[0]
    partes = filename_without_ext.rsplit('_', 1)
    
    if len(partes) > 1 and re.search(r'\d', partes[-1]):
        base_name = partes[0]
    else:
        base_name = filename_without_ext.rsplit('_', 2)[0]
    
    img = cv2.imread(full_path, cv2.IMREAD_UNCHANGED)
    if img is None:
        print(f"Erro ao ler {full_path}, pulando...")
        continue
    
    h, w = img.shape[:2]
    
    # Assumindo 1 objeto por imagem, bounding box ocupa toda a imagem
    x_center, y_center = 0.5, 0.5
    width_norm, height_norm = 1.0, 1.0
    
    # Descobre a classe pelo nome base
    class_id = class_map[base_name]
    label_line = f"{class_id} {x_center} {y_center} {width_norm} {height_norm}"
    
    # Salva o arquivo de label no mesmo diretório da imagem
    txt_path = os.path.join(dir_name, os.path.splitext(filename)[0] + ".txt")
    with open(txt_path, "w") as f:
        f.write(label_line)
    
    print(f"Label criado: {txt_path}")

# --- 4️⃣ Gerar arquivo com nomes das classes ---
names_array = [None] * len(class_map)
for name, idx in class_map.items():
    names_array[idx] = name

names_str = f"names: {names_array}\n"

# Salva o arquivo de classes na raiz do dataset
classes_file = os.path.join(images_path, "classes.yaml")

with open(classes_file, "w", encoding="utf-8") as f:
    f.write(names_str)

print(f"\nArquivo de classes criado: {classes_file}")
print(names_str)

# --- 5️⃣ Exibir o total de classes ---
print(f"\nTotal de classes criadas: {len(class_map)}")