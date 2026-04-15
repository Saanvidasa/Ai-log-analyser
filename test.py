import google.generativeai as genai

print("\n=== AVAILABLE MODELS ===")
for m in genai.list_models():
    print(m.name)
print("========================\n")