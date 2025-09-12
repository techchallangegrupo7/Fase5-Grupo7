from ultralytics import YOLO

# Carregar o modelo treinado
# [cite_start]O caminho para o arquivo .pt foi obtido a partir dos seus logs de treinamento [cite: 109]
model_path = r'D:\_fiap\vincula git\Fase5-Grupo7\app\runs\train\yolov8s-custom\weights\last.pt'
model = YOLO(model_path)

# Caminho para a imagem na qual você deseja executar a detecção
# Substitua 'caminho/para/sua/imagem.jpg' pelo caminho real da sua imagem
image_path = 'aws_arch3.png'


# Realiza a detecção de objetos na imagem e salva os resultados.
# O parâmetro 'save=True' salva a imagem com as caixas desenhadas.
# O parâmetro 'conf' define o nível de confiança (0.25 é o padrão).
results = model.predict(source=image_path, conf=0.05, save=True)

# Os resultados, incluindo a imagem com as caixas, serão salvos em um diretório como 'runs/detect/predict'.
# O nome da pasta será gerado automaticamente.
print(f"Detecção concluída! A imagem com as caixas delimitadoras foi salva em {results[0].save_dir}.")