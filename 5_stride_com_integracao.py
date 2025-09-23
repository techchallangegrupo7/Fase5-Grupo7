
##
import google.generativeai as genai

# Configure sua chave de API aqui
genai.configure(api_key="COLOQUE SUA CHAVE")



# for m in genai.list_models():
#     if 'generateContent' in m.supported_generation_methods:
#         print(m.name)

# Lista dos componentes da sua arquitetura
componentes = ['AWS-Backup']

# Escolhe o modelo
model = genai.GenerativeModel('gemini-1.5-flash')

stride_results = []

for componente in componentes:
    prompt_stride = f"""
    Analise o componente de arquitetura {componente} usando o modelo de ameaças STRIDE. 

    Para cada categoria do STRIDE (Spoofing, Tampering, Repudiation, Information Disclosure, Denial of Service e Elevation of Privilege), identifique as possíveis ameaças e vulnerabilidades específicas desse componente.

    Formate a resposta como uma lista, com a categoria do STRIDE como título.
    """
    
    # Envia o prompt para o Gemini
    response = model.generate_content(prompt_stride)
    
    # Imprime a análise do STRIDE para o componente
    print(f"--- Análise STRIDE para {componente} ---\n")
    print(response.text)
    
    # Aqui você pode salvar a resposta para usar no próximo prompt,
    # como em uma lista ou arquivo.    
    stride_results.append((componente, response.text))

    # Supondo que você salvou a saída do prompt STRIDE em uma variável
    resultado_do_prompt_anterior = response.text

    prompt_mitigacoes = f"""
    Com base nas seguintes ameaças de segurança, forneça direcionamentos e boas práticas para mitigar cada uma delas.

    **Ameaças de Segurança:**
    {resultado_do_prompt_anterior}

    Liste as mitigações de forma clara e objetiva para cada categoria de ameaça (Spoofing, Tampering, etc.).
    """

    # Envia o prompt para o Gemini para obter as mitigações
    response_mitigacoes = model.generate_content(prompt_mitigacoes)

    # Imprime as mitigações
    print("\n--- Mitigações Sugeridas ---\n")
    print(response_mitigacoes.text)