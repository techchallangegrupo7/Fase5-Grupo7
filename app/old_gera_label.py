import os
import cv2

# --- Caminhos ---
images_path = "dataset"   # pasta com PNGs
labels_path = "dataset"   # pasta onde os labels serão salvos
os.makedirs(labels_path, exist_ok=True)

# --- 1️⃣ Criar class_map automaticamente ---
png_files = [f for f in os.listdir(images_path) if f.endswith(".png")]

# pegar nomes base únicos (sem extensão) -> cada nome vira uma classe
class_names = sorted({os.path.splitext(f)[0] for f in png_files})

# gerar ID único para cada classe
class_map = {name: idx for idx, name in enumerate(class_names)}

print("Classes detectadas:")
for name, idx in class_map.items():
    print(f"{idx}: {name}")

# --- 2️⃣ Gerar labels YOLO ---
for filename in png_files:
    img_path = os.path.join(images_path, filename)
    img = cv2.imread(img_path, cv2.IMREAD_UNCHANGED)  # lê com canal alpha

    if img is None:
        print(f"Erro ao ler {filename}, pulando...")
        continue

    h, w = img.shape[:2]

    # Assumindo 1 objeto por imagem, bounding box ocupa toda a imagem
    x_center = 0.5
    y_center = 0.5
    width_norm = 1.0
    height_norm = 1.0

    # descobrir classe pelo nome base
    base_name = os.path.splitext(filename)[0]
    class_id = class_map[base_name]

    # criar linha do label
    label_line = f"{class_id} {x_center} {y_center} {width_norm} {height_norm}"

    # salvar em .txt
    txt_path = os.path.join(labels_path, base_name + ".txt")
    with open(txt_path, "w") as f:
        f.write(label_line)

    print(f"Label criado: {txt_path}")

# --- 3️⃣ Gerar arquivo com nomes das classes (na ordem dos IDs) ---
# cria lista onde cada posição corresponde ao índice da classe
names_array = [None] * len(class_map)
for name, idx in class_map.items():
    names_array[idx] = name

names_str = f"names: {names_array}\n"

# salvar um nível acima da raiz do dataset
root_dir = os.path.dirname(images_path)   # volta uma pasta
classes_file = os.path.join(root_dir, "classes.yaml")

with open(classes_file, "w", encoding="utf-8") as f:
    f.write(names_str)

print(f"\nArquivo de classes criado: {classes_file}")
print(names_str)
