from modules.ollama_analyzer import check_ollama, list_models

print("Ollama reachable:", check_ollama())

if check_ollama():
    print("Available models:")
    for model in list_models():
        print(f"  - {model}")
