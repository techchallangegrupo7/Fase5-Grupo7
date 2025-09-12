import os
import shutil
import re
from sklearn.model_selection import train_test_split

# Caminhos
original_images_path = 'dataset/images_aug'
original_labels_path = 'dataset/labels_aug'
output_path = 'dataset/yolo'

# Cria o diretório de saída com a estrutura do YOLO
def create_yolo_structure(base_path):
    for subset in ['train', 'val', 'test']:
        os.makedirs(os.path.join(base_path, subset, 'images'), exist_ok=True)
        os.makedirs(os.path.join(base_path, subset, 'labels'), exist_ok=True)

create_yolo_structure(output_path)

# Função para extrair o "id base"
def get_base_id(filename):
    # Encontra o padrão _aug seguido de dígitos, ou o ponto e a extensão
    match = re.search(r'_aug\d+', filename)
    if match:
        return filename[:match.start()]
    else:
        return os.path.splitext(filename)[0]

# Lista todas as imagens
all_images = [f for f in os.listdir(original_images_path) if f.endswith(('.png', '.jpg', '.jpeg'))]

# Agrupa as imagens por ID base (classe)
groups = {}
for img in all_images:
    base_id = get_base_id(img)
    groups.setdefault(base_id, []).append(img)

# Divide os IDs base (representando as classes)
base_ids = list(groups.keys())
train_ids, val_test_ids = train_test_split(base_ids, test_size=0.2, random_state=42)
val_ids, test_ids = train_test_split(val_test_ids, test_size=0.5, random_state=42)

def copy_files(group_ids, dest_folder):
    dest_images_path = os.path.join(output_path, dest_folder, 'images')
    dest_labels_path = os.path.join(output_path, dest_folder, 'labels')

    for gid in group_ids:
        for img_file in groups.get(gid, []):
            # Obtém os caminhos de origem e destino da imagem
            src_img = os.path.join(original_images_path, img_file)
            dest_img = os.path.join(dest_images_path, img_file)
            
            # Copia a imagem
            if os.path.exists(src_img):
                shutil.copy(src_img, dest_img)
            
            # Obtém os caminhos de origem e destino do arquivo de anotação
            label_file = os.path.splitext(img_file)[0] + '.txt'
            src_label = os.path.join(original_labels_path, label_file)
            dest_label = os.path.join(dest_labels_path, label_file)
            
            # Copia o arquivo de anotação
            if os.path.exists(src_label):
                shutil.copy(src_label, dest_label)
            else:
                print(f"Aviso: Label não encontrada para {img_file}")

# Copia os arquivos para os respectivos diretórios
copy_files(train_ids, 'train')
copy_files(val_ids, 'val')
copy_files(test_ids, 'test')

# Cria o arquivo data.yaml
with open(os.path.join(output_path, 'data.yaml'), 'w') as f:
    f.write('train: train/images\n')
    f.write('val: val/images\n')
    f.write('test: test/images\n')
    f.write(f'nc: {len(groups)}\n')
    f.write("names: [SUBSTITUTE_WITH_CLASS_NAMES]\n")

print("Divisão concluída com sucesso!")