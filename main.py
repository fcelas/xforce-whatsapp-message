import os
from datetime import datetime
import pytz

os.system('python vuln24h-xforce-api.py')

timestamp_today = datetime.now(pytz.timezone('America/Fortaleza')).strftime('%d-%m-%Y')

json_filename = os.path.join('results', f'vulnerabilidades-{timestamp_today}.json')

if os.path.exists(json_filename):
    os.system('python json-parse.py')
else:
    print('Nenhum arquivo de vulnerabilidades foi gerado.')
