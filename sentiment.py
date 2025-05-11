from transformers import pipeline
import sys
import json


analyzer = pipeline("sentiment-analysis")

text = sys.argv[1]
result = analyzer(text)[0]

print(json.dumps(result))
