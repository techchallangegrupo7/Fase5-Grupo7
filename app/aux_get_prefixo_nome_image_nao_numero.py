import os

def pegar_conteudo_apos_ultimo_sublinhado(caminho_pasta):
    """
    Percorre uma pasta e suas subpastas para extrair a parte do nome
    de cada arquivo que vem depois do último '_'.
    
    Args:
        caminho_pasta (str): O caminho da pasta raiz para começar a busca.
    
    Returns:
        list: Uma lista com os sufixos dos arquivos encontrados.
    """
    sufixos = []
    
    # Percorre a pasta e suas subpastas
    for pasta_atual, _, arquivos in os.walk(caminho_pasta):
        for nome_arquivo in arquivos:
            # Tenta dividir o nome do arquivo a partir do último '_'
            partes = nome_arquivo.rsplit('_', 1)
            
            # Se a divisão resultou em duas partes, pegamos a segunda (o sufixo)
            if len(partes) > 1:
                sufixo = partes[1]
                sufixos.append(sufixo)
            else:
                # Caso o arquivo não tenha '_', ele é ignorado ou você pode tratá-lo aqui
                print(f"Atenção: Arquivo sem '_' encontrado, pulando: {nome_arquivo}")
                
    return sufixos

# Exemplo de uso
if __name__ == "__main__":
    # Defina o caminho para a sua pasta.
    caminho_raiz = "dataset\\images"
    
    if os.path.isdir(caminho_raiz):
        lista_sufixos = pegar_conteudo_apos_ultimo_sublinhado(caminho_raiz)
        
        # Imprime a lista completa
        print("Sufixos de arquivos (conteúdo após o último '_'):")
        for sufixo in lista_sufixos:
            print(f"- {sufixo}")
            
        print(f"\nTotal de sufixos encontrados: {len(lista_sufixos)}")
        
        # Opcional: para ver apenas os sufixos únicos
        sufixos_unicos = list(set(lista_sufixos))
        print(f"Total de sufixos únicos: {len(sufixos_unicos)}")
        print("Sufixos únicos:", sufixos_unicos)
        
    else:
        print(f"Erro: O caminho '{caminho_raiz}' não foi encontrado.")