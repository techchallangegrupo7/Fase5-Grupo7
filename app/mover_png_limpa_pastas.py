import os
import shutil

def mover_pngs_e_limpar(caminho_raiz):
    """
    Move todos os arquivos .png das subpastas para o diretório raiz e
    deleta os outros arquivos.

    Args:
        caminho_raiz (str): O caminho da pasta raiz, onde os arquivos .png serão movidos.
    """
    if not os.path.exists(caminho_raiz):
        print(f"O caminho '{caminho_raiz}' não existe. Verifique o caminho e tente novamente.")
        return

    # Percorre a pasta raiz e suas subpastas
    for pasta_atual, subpastas, arquivos in os.walk(caminho_raiz):
        if pasta_atual == caminho_raiz:
            continue

        for nome_arquivo in arquivos:
            caminho_completo_origem = os.path.join(pasta_atual, nome_arquivo)
            
            if nome_arquivo.lower().endswith('.png'):
                caminho_completo_destino = os.path.join(caminho_raiz, nome_arquivo)
                
                try:
                    if os.path.exists(caminho_completo_destino):
                        nome_base, extensao = os.path.splitext(nome_arquivo)
                        contador = 1
                        while os.path.exists(os.path.join(caminho_raiz, f"{nome_base}_{contador}{extensao}")):
                            contador += 1
                        novo_nome = f"{nome_base}_{contador}{extensao}"
                        caminho_completo_destino = os.path.join(caminho_raiz, novo_nome)
                        print(f"Arquivo '{nome_arquivo}' já existe. Movendo como '{novo_nome}'.")

                    shutil.move(caminho_completo_origem, caminho_completo_destino)
                    print(f"Arquivo movido: {nome_arquivo}")
                except shutil.Error as e:
                    print(f"Erro ao mover o arquivo {nome_arquivo}: {e}")
            else:
                try:
                    os.remove(caminho_completo_origem)
                    print(f"Arquivo deletado: {nome_arquivo}")
                except OSError as e:
                    print(f"Erro ao deletar o arquivo {nome_arquivo}: {e}")

    # Remove as subpastas vazias
    for pasta_atual, subpastas, arquivos in os.walk(caminho_raiz, topdown=False):
        if not subpastas and not arquivos and pasta_atual != caminho_raiz:
            try:
                os.rmdir(pasta_atual)
                print(f"Pasta vazia removida: {pasta_atual}")
            except OSError as e:
                print(f"Erro ao remover a pasta {pasta_atual}: {e}")

# Exemplo de uso
if __name__ == "__main__":
    # Caminho relativo a partir da raiz do projeto
    caminho_relativo = "data\\images\\aws_icons"
    
    # Cria o caminho completo usando o diretório atual do script
    pasta_raiz_aws = os.path.join(os.getcwd(), caminho_relativo)
    
    mover_pngs_e_limpar(pasta_raiz_aws)