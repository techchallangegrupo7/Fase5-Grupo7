import os

def pegar_nome_base(caminho_pasta):
    """
    Percorre uma pasta e suas subpastas para extrair a parte
    do nome de cada arquivo que precede o último '_'.
    
    Args:
        caminho_pasta (str): O caminho da pasta raiz para começar a busca.
    
    Returns:
        list: Uma lista com os nomes base dos arquivos encontrados.
    """
    nomes_base = []
    
    # Percorre a pasta e suas subpastas
    for pasta_atual, _, arquivos in os.walk(caminho_pasta):
        for nome_arquivo in arquivos:
            # Tenta encontrar o último '_' no nome do arquivo
            # e pegar a parte antes dele
            partes = nome_arquivo.rsplit('_', 1)
            
            # A primeira parte da lista é o nome que você quer
            nome_base = partes[0]
            
            # Adiciona o nome base à lista
            nomes_base.append(nome_base)
            
    return nomes_base

# Exemplo de uso
if __name__ == "__main__":
    # Defina o caminho para a sua pasta.
    caminho_raiz = "dataset\\images"
    
    if os.path.isdir(caminho_raiz):
        lista_nomes_base = pegar_nome_base(caminho_raiz)
        
        # Imprime a lista completa
        print("Nomes de arquivos (até o último '_'):")
        for nome in lista_nomes_base:
            print(f"- {nome}")
            
        print(f"\nTotal de arquivos encontrados: {len(lista_nomes_base)}")
        
    else:
        print(f"Erro: O caminho '{caminho_raiz}' não foi encontrado.")