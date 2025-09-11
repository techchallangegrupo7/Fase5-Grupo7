import os
import shutil
from sklearn.model_selection import train_test_split

# Define os caminhos para os dados originais (imagens e anotações)
original_images_path = 'dataset/images_aug'
original_labels_path = 'dataset/labels_aug'  # <-- Caminho correto para as labels

# Define os caminhos onde as pastas divididas serão criadas
output_path = 'dataset/yolo'



# Cria o diretório de saída
os.makedirs(output_path, exist_ok=True)

# Lista todos os arquivos de imagem
all_images = [os.path.join(original_images_path, f) for f in os.listdir(original_images_path) if f.endswith('.png')]

# Divide os dados em treinamento, validação e teste
train_images, val_test_images = train_test_split(all_images, test_size=0.3, random_state=42)
val_images, test_images = train_test_split(val_test_images, test_size=0.5, random_state=42)

# Função para copiar arquivos
def copy_files(file_list, dest_folder):
    dest_images_path = os.path.join(output_path, dest_folder, 'images')
    dest_labels_path = os.path.join(output_path, dest_folder, 'labels')
    os.makedirs(dest_images_path, exist_ok=True)
    os.makedirs(dest_labels_path, exist_ok=True)
    
    for image_file in file_list:
        # Copia a imagem
        shutil.copy(image_file, dest_images_path)
        
        # Constrói o caminho para a anotação correspondente usando a pasta de labels
        base_filename = os.path.basename(image_file)
        label_file = os.path.join(original_labels_path, base_filename.replace('.png', '.txt'))
        
        if os.path.exists(label_file):
            shutil.copy(label_file, dest_labels_path)
        else:
            print(f"Aviso: Arquivo de label não encontrado para {base_filename}")

# Copia os arquivos para as pastas criadas
copy_files(train_images, 'train')
copy_files(val_images, 'val')
copy_files(test_images, 'test')

# Cria o arquivo data.yaml
with open(os.path.join(output_path, 'data.yaml'), 'w') as f:
    f.write('train: train/images\n')
    f.write('val: val/images\n')
    f.write('test: test/images\n')
    f.write('nc: 828\n')
    f.write("names: [SUBSTITUTE_WITH_CLASS_NAMES]\n")  # Substitua com os nomes reais das classes

print(f"\nFINAL")

