import shutil
import time
from ultralytics import YOLO

def main():
    data_yaml = 'dataset/yolo/data.yaml'
    model = YOLO('yolov8s.pt')
    epochs = 50
    model.train(
        data=data_yaml,
        epochs=epochs,
        imgsz=416,
        batch=16,
        project='runs/train',
        name='yolov8s-custom',
        save_period=5
    )

    weights_dir = 'runs/train/yolov8s-custom/weights'
    for epoch in range(1, epochs + 1):
        src = f'{weights_dir}/epoch{epoch}.pt'
        dst = f'{weights_dir}/treinamento_yolo_aws_epoca_{epoch}.pt'
        try:
            shutil.copy(src, dst)
        except FileNotFoundError:
            pass

if __name__ == "__main__":
    main()