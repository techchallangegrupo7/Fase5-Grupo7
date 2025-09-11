import os
import re

def verificar_padrao_png(caminho_pasta):
    """
    Verifica se todos os arquivos .png em uma pasta e suas subpastas
    seguem o padrão '_<número>.png' no final do nome.
    
    Args:
        caminho_pasta (str): O caminho da pasta a ser verificada.
    """
    arquivos_fora_do_padrao = []
    
    # Padrão de regex para verificar se o nome do arquivo termina com _<número>.png
    regex_padrao = re.compile(r'_\d+\.png$', re.IGNORECASE)
    
    # Percorre a pasta e suas subpastas
    for pasta_atual, _, arquivos in os.walk(caminho_pasta):
        for nome_arquivo in arquivos:
            # A verificação é apenas para arquivos .png
            if nome_arquivo.lower().endswith('.png'):
                # Usa search para ver se o padrão é encontrado no nome do arquivo
                if not regex_padrao.search(nome_arquivo):
                    caminho_completo = os.path.join(pasta_atual, nome_arquivo)
                    arquivos_fora_do_padrao.append(caminho_completo)
                    
    if arquivos_fora_do_padrao:
        print("Os seguintes arquivos .png não seguem o padrão '_<número>.png':")
        for arquivo in arquivos_fora_do_padrao:
            print(f"- {arquivo}")
    else:
        print("Parabéns! Todos os arquivos .png na pasta seguem o padrão esperado.")
        
# Exemplo de uso
if __name__ == "__main__":
    # Defina o caminho da sua pasta.
    caminho_da_pasta = "dataset\\images"
    
    if os.path.isdir(caminho_da_pasta):
        verificar_padrao_png(caminho_da_pasta)
    else:
        print(f"Erro: O caminho '{caminho_da_pasta}' não foi encontrado.")