import os
import cv2
import numpy as np
from PIL import Image, ImageEnhance
import random
import shutil

# Configurações
input_img_dir = 'dataset/images'
input_lbl_dir = 'dataset/labels'  # <-- Caminho correto para as labels
output_img_dir = 'dataset/images_aug'
output_lbl_dir = 'dataset/labels_aug'
num_aug = 12  # Quantas variações por imagem

os.makedirs(output_img_dir, exist_ok=True)
os.makedirs(output_lbl_dir, exist_ok=True)

def random_transform(img):
    # Rotação
    angle = random.uniform(-25, 25)
    img = img.rotate(angle)

    # Brilho
    enhancer = ImageEnhance.Brightness(img)
    img = enhancer.enhance(random.uniform(0.7, 1.3))

    # Contraste
    enhancer = ImageEnhance.Contrast(img)
    img = enhancer.enhance(random.uniform(0.7, 1.3))

    # Flip horizontal
    if random.random() > 0.5:
        img = img.transpose(Image.FLIP_LEFT_RIGHT)

    # Ruído
    img_np = np.array(img)
    noise = np.random.normal(0, 10, img_np.shape).astype(np.uint8)
    img_np = cv2.add(img_np, noise)
    img = Image.fromarray(img_np)

    return img

for img_name in os.listdir(input_img_dir):
    if not img_name.lower().endswith(('.png', '.jpg', '.jpeg')):
        continue
    img_path = os.path.join(input_img_dir, img_name)
    lbl_path = os.path.join(input_lbl_dir, os.path.splitext(img_name)[0] + '.txt')

    # Copia original
    shutil.copy(img_path, os.path.join(output_img_dir, img_name))
    shutil.copy(lbl_path, os.path.join(output_lbl_dir, os.path.splitext(img_name)[0] + '.txt'))

    # Gera variações
    for i in range(num_aug):
        img = Image.open(img_path)
        img_aug = random_transform(img)
        aug_img_name = f"{os.path.splitext(img_name)[0]}_aug{i}.png"
        img_aug.save(os.path.join(output_img_dir, aug_img_name))
        # Label é igual (bounding box cobre o ícone inteiro)
        shutil.copy(lbl_path, os.path.join(output_lbl_dir, f"{os.path.splitext(img_name)[0]}_aug{i}.txt"))

print("Data augmentation finalizada! Imagens e labels salvos em:", output_img_dir, output_lbl_dir)