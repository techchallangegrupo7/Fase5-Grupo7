import os
import shutil
import random
from PIL import Image, ImageDraw
import math
from typing import List, Tuple
from sklearn.model_selection import train_test_split

# --- 1. Definição de Caminhos e Parâmetros ---
ICONS_DIR = 'dataset/images'
ICONS_LABELS_DIR = 'dataset/labels'

OUTPUT_DATASET_DIR = 'dataset/yolo'
TEMP_SYNTHETIC_IMG_DIR = os.path.join(OUTPUT_DATASET_DIR, 'temp_images_synthetic')
TEMP_SYNTHETIC_LBL_DIR = os.path.join(OUTPUT_DATASET_DIR, 'temp_labels_synthetic')

NUM_SYNTHETIC_IMAGES = 8000  # número alvo de imagens
IMAGE_SIZE = (640, 640)
MIN_ICONS_PER_IMAGE = 1
MAX_ICONS_PER_IMAGE = 5
SCALE_RANGE = (0.2, 0.5)

SPLIT_RATIOS = {'train': 0.7, 'val': 0.15, 'test': 0.15}
RANDOM_STATE = 42
random.seed(RANDOM_STATE)

# --- 2. Funções Auxiliares (Geração de Dados Sintéticos) ---
def generate_random_background(size: Tuple[int, int]) -> Image.Image:
    """Gera fundos sintéticos aleatórios (sólido, gradiente ou linhas)."""
    bg_type = random.choice(['solid', 'gradient', 'lines'])
    img = Image.new('RGB', size, color='white')
    draw = ImageDraw.Draw(img)

    if bg_type == 'solid':
        color = tuple(random.randint(0, 255) for _ in range(3))
        img = Image.new('RGB', size, color)

    elif bg_type == 'gradient':
        color1 = tuple(random.randint(0, 255) for _ in range(3))
        color2 = tuple(random.randint(0, 255) for _ in range(3))
        for y in range(size[1]):
            r = int(color1[0] + (color2[0] - color1[0]) * y / size[1])
            g = int(color1[1] + (color2[1] - color1[1]) * y / size[1])
            b = int(color1[2] + (color2[2] - color1[2]) * y / size[1])
            draw.line([(0, y), (size[0], y)], fill=(r, g, b))

    elif bg_type == 'lines':
        color = tuple(random.randint(0, 255) for _ in range(3))
        line_color = tuple(random.randint(0, 255) for _ in range(3))
        img = Image.new('RGB', size, color)
        draw = ImageDraw.Draw(img)
        for _ in range(random.randint(5, 20)):
            x1, y1 = random.randint(0, size[0]), random.randint(0, size[1])
            x2, y2 = random.randint(0, size[0]), random.randint(0, size[1])
            draw.line([(x1, y1), (x2, y2)], fill=line_color, width=random.randint(1, 5))

    return img

def load_data():
    """Carrega ícones e seus rótulos."""
    icons, labels_map = [], {}
    for filename in os.listdir(ICONS_DIR):
        if filename.lower().endswith(('.png', '.jpg', '.jpeg')):
            base_name = os.path.splitext(filename)[0]
            icon_path = os.path.join(ICONS_DIR, filename)
            label_path = os.path.join(ICONS_LABELS_DIR, base_name + '.txt')
            if os.path.exists(label_path):
                icons.append(icon_path)
                with open(label_path, 'r') as f:
                    labels_map[icon_path] = f.readline().strip()
    if not icons:
        raise ValueError("Não há ícones suficientes nos diretórios especificados.")
    return icons, labels_map

def convert_bbox_coords(new_coords: Tuple[int, int, int, int], new_img_size: Tuple[int, int]) -> List[float]:
    """Converte bounding box para formato YOLO (normalizado)."""
    x_min, y_min, x_max, y_max = new_coords
    img_width, img_height = new_img_size
    x_c = (x_min + x_max) / 2
    y_c = (y_min + y_max) / 2
    w = x_max - x_min
    h = y_max - y_min
    return [x_c / img_width, y_c / img_height, w / img_width, h / img_height]

def create_yolo_structure_final():
    """Cria a estrutura final do dataset YOLO."""
    for subset in ['train', 'val', 'test']:
        os.makedirs(os.path.join(OUTPUT_DATASET_DIR, subset, 'images'), exist_ok=True)
        os.makedirs(os.path.join(OUTPUT_DATASET_DIR, subset, 'labels'), exist_ok=True)

# --- 3. Geração e Divisão Manual dos Dados ---
def generate_and_split_data():
    icons, labels_map = load_data()
    num_classes = len(icons)

    os.makedirs(TEMP_SYNTHETIC_IMG_DIR, exist_ok=True)
    os.makedirs(TEMP_SYNTHETIC_LBL_DIR, exist_ok=True)

    min_images_needed = num_classes / SPLIT_RATIOS['val']
    print(f"Total de classes encontradas: {num_classes}")
    print(f"Mínimo recomendado de imagens sintéticas: {math.ceil(min_images_needed)}")
    if NUM_SYNTHETIC_IMAGES < math.ceil(min_images_needed):
        raise ValueError(f"O número de imagens sintéticas ({NUM_SYNTHETIC_IMAGES}) é muito baixo. "
                         f"Aumente para pelo menos {math.ceil(min_images_needed)}.")

    image_label_pairs, image_to_class_id = [], {}

    # --- Garante pelo menos 3 exemplos por classe ---
    print(f"\nGerando {num_classes * 3} imagens garantidas (>=3 por classe)...")
    guarantee_list = icons * 3
    random.shuffle(guarantee_list)

    for i, icon_path in enumerate(guarantee_list):
        bg_img = generate_random_background(IMAGE_SIZE).convert("RGB")
        icon_img = Image.open(icon_path).convert("RGBA")
        class_id = labels_map[icon_path].split()[0]

        scale = random.uniform(*SCALE_RANGE)
        icon_width = int(icon_img.width * scale)
        icon_height = int(icon_img.height * scale)
        icon_img = icon_img.resize((icon_width, icon_height), Image.LANCZOS)

        x = random.randint(0, IMAGE_SIZE[0] - icon_width)
        y = random.randint(0, IMAGE_SIZE[1] - icon_height)
        bg_img.paste(icon_img, (x, y), icon_img)

        bbox = convert_bbox_coords((x, y, x + icon_width, y + icon_height), IMAGE_SIZE)
        label = f"{class_id} {' '.join(map(str, bbox))}"

        filename = f"guaranteed_img_{i:04d}.jpg"
        label_filename = f"{os.path.splitext(filename)[0]}.txt"

        bg_img.save(os.path.join(TEMP_SYNTHETIC_IMG_DIR, filename))
        with open(os.path.join(TEMP_SYNTHETIC_LBL_DIR, label_filename), 'w') as f:
            f.write(label)

        image_label_pairs.append((filename, label_filename))
        image_to_class_id[filename] = int(class_id)

    # --- Geração aleatória até completar NUM_SYNTHETIC_IMAGES ---
    print("\nGerando imagens sintéticas adicionais...")
    for i in range(len(guarantee_list), NUM_SYNTHETIC_IMAGES):
        bg_img = generate_random_background(IMAGE_SIZE).convert("RGB")
        num_icons = random.randint(MIN_ICONS_PER_IMAGE, MAX_ICONS_PER_IMAGE)
        synthetic_labels = []

        for _ in range(num_icons):
            icon_path = random.choice(icons)
            icon_img = Image.open(icon_path).convert("RGBA")
            class_id = labels_map[icon_path].split()[0]

            scale = random.uniform(*SCALE_RANGE)
            icon_width = int(icon_img.width * scale)
            icon_height = int(icon_img.height * scale)
            icon_img = icon_img.resize((icon_width, icon_height), Image.LANCZOS)

            x = random.randint(0, IMAGE_SIZE[0] - icon_width)
            y = random.randint(0, IMAGE_SIZE[1] - icon_height)
            bg_img.paste(icon_img, (x, y), icon_img)

            bbox = convert_bbox_coords((x, y, x + icon_width, y + icon_height), IMAGE_SIZE)
            synthetic_labels.append(f"{class_id} {' '.join(map(str, bbox))}")

        filename = f"synthetic_img_{i:04d}.jpg"
        label_filename = f"{os.path.splitext(filename)[0]}.txt"

        bg_img.save(os.path.join(TEMP_SYNTHETIC_IMG_DIR, filename))
        with open(os.path.join(TEMP_SYNTHETIC_LBL_DIR, label_filename), 'w') as f:
            f.write('\n'.join(synthetic_labels))

        image_label_pairs.append((filename, label_filename))
        image_to_class_id[filename] = int(synthetic_labels[0].split()[0])

    print("\n✅ Geração de dados sintéticos concluída!")

    # --- Divisão estratificada ---
    print("\nIniciando divisão estratificada...")
    train_files, val_test_files = train_test_split(
        image_label_pairs,
        test_size=SPLIT_RATIOS['val'] + SPLIT_RATIOS['test'],
        random_state=RANDOM_STATE,
        stratify=[image_to_class_id[pair[0]] for pair in image_label_pairs]
    )

    # Segundo split sem stratify (evita erro de classe única)
    val_files, test_files = train_test_split(
        val_test_files,
        test_size=SPLIT_RATIOS['test'] / (SPLIT_RATIOS['val'] + SPLIT_RATIOS['test']),
        random_state=RANDOM_STATE
    )

    create_yolo_structure_final()

    # Copia arquivos para pastas finais
    for subset, files in [('train', train_files), ('val', val_files), ('test', test_files)]:
        for img_file, lbl_file in files:
            shutil.copy(os.path.join(TEMP_SYNTHETIC_IMG_DIR, img_file),
                        os.path.join(OUTPUT_DATASET_DIR, subset, 'images', img_file))
            shutil.copy(os.path.join(TEMP_SYNTHETIC_LBL_DIR, lbl_file),
                        os.path.join(OUTPUT_DATASET_DIR, subset, 'labels', lbl_file))

    # Cria data.yaml
    class_id_to_name = {int(label.split()[0]): os.path.splitext(os.path.basename(icon_path))[0]
                        for icon_path, label in labels_map.items()}
    sorted_class_names = [class_id_to_name[i] for i in sorted(class_id_to_name)]
    yaml_content = (
        f"train: {os.path.join('train', 'images')}\n"
        # f"train: {os.path.join('..', 'yolo', 'train', 'images')}\n"
        f"val: {os.path.join('val', 'images')}\n"
        # f"val: {os.path.join('..', 'yolo', 'val', 'images')}\n"
        f"test: {os.path.join('test', 'images')}\n"
        # f"test: {os.path.join('..', 'yolo', 'test', 'images')}\n"
        f"nc: {len(sorted_class_names)}\n"
        f"names: {sorted_class_names}\n"
    )
    with open(os.path.join(OUTPUT_DATASET_DIR, 'data.yaml'), 'w') as f:
        f.write(yaml_content)

    print("✅ Dataset pronto para treino em:", OUTPUT_DATASET_DIR)

    # Limpeza
    shutil.rmtree(TEMP_SYNTHETIC_IMG_DIR)
    shutil.rmtree(TEMP_SYNTHETIC_LBL_DIR)
    print("Pastas temporárias removidas.")

if __name__ == '__main__':
    generate_and_split_data()
