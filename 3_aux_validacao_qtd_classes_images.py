import glob
from collections import Counter
import os

def processar_diretorios_e_exportar(diretorios, nome_arquivo_saida):
    """
    Processa arquivos .txt em múltiplos diretórios e exporta um relatório
    individual para cada diretório para um arquivo de texto.
    """
    print(f"Iniciando a leitura e contagem. O relatório será exportado para '{nome_arquivo_saida}'...")
    
    try:
        # Abre o arquivo de saída no modo de escrita ('w')
        with open(nome_arquivo_saida, 'w', encoding='utf-8') as arquivo_saida:
            
            # Percorre cada diretório na lista
            for diretorio in diretorios:
                # Escreve o cabeçalho do relatório no arquivo
                arquivo_saida.write("\n" + "="*50 + "\n")
                arquivo_saida.write(f"  RELATÓRIO PARA O DIRETÓRIO: '{diretorio}'\n")
                arquivo_saida.write("="*50 + "\n")
                
                contagem_local = Counter()
                caminho_busca = os.path.join(diretorio, '*.txt')
                arquivos_txt = glob.glob(caminho_busca)
                
                if not arquivos_txt:
                    arquivo_saida.write(f"  Nenhum arquivo .txt encontrado no diretório '{diretorio}'.\n")
                    continue
                    
                for arquivo in arquivos_txt:
                    try:
                        with open(arquivo, 'r', encoding='utf-8') as f_leitura:
                            for linha in f_leitura:
                                linha = linha.strip()
                                if not linha:
                                    continue
                                
                                partes = linha.split()
                                if partes:
                                    primeira_coluna = partes[0]
                                    try:
                                        numero = int(primeira_coluna)
                                        contagem_local[numero] += 1
                                    except ValueError:
                                        # Opcional: registrar aviso no arquivo
                                        pass
                    except Exception as e:
                        arquivo_saida.write(f"  Erro ao ler o arquivo '{arquivo}': {e}\n")
                        
                if not contagem_local:
                    arquivo_saida.write("  Nenhum número foi encontrado na primeira coluna dos arquivos.\n")
                else:
                    numeros_encontrados_ordenados = sorted(contagem_local.keys())
                    for numero in numeros_encontrados_ordenados:
                        contagem = contagem_local[numero]
                        arquivo_saida.write(f"  O NÚMERO {numero}, ENCONTRADO {contagem} vezes neste diretório.\n")
        
        # Confirmação final no terminal
        print(f"\nProcessamento concluído. O relatório foi exportado com sucesso para '{nome_arquivo_saida}'.")
        
    except Exception as e:
        print(f"Erro ao exportar o arquivo de relatório: {e}")

# Lista dos diretórios a serem processados
diretorios_a_processar = ['dataset/yolo_sem_rotacao/test/labels', 'dataset/yolo_sem_rotacao/val/labels', 'dataset/yolo_sem_rotacao/train/labels']

# Nome do arquivo de saída
nome_do_arquivo = 'relatorio.txt'

# Executa a função
processar_diretorios_e_exportar(diretorios_a_processar, nome_do_arquivo)
