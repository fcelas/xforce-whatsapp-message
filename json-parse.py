import json
from datetime import datetime
import pytz
import re
import subprocess
import os

whatsapp_phone_numbers_str = os.environ.get("WHATSAPP_PHONE_NUMBERS", "")
whatsapp_phone_numbers = whatsapp_phone_numbers_str.split(',')
whatsapp_phone_id = os.environ.get("WHATSAPP_NUMBER_ID")
whatsapp_token = os.environ.get("WHATSAPP_TOKEN")


def getTime(date_str, time_zone):
    original_format = "%Y-%m-%dT%H:%M:%SZ"
    destination_format = "%d-%m-%Y %H:%M:%S"
    time_utc = datetime.strptime(date_str, original_format)
    time_fortaleza = time_utc.replace(tzinfo=pytz.utc).astimezone(pytz.timezone(time_zone))
    return time_fortaleza.strftime(destination_format)

def isCVELink(link):
    cve_pattern = re.compile(r'https://www\.cve\.org/.*')
    return bool(cve_pattern.match(link))

timestamp_today = datetime.now(pytz.timezone('America/Fortaleza')).strftime('%d-%m-%Y')

json_filename = os.path.join('results', f'vulnerabilidades-{timestamp_today}.json')

with open(json_filename, 'r') as file:
    json_data = json.load(file)

vulnerabilities = json_data['rows']

for vulnerability in vulnerabilities:
    title = vulnerability.get('title', '')
    stdcode = vulnerability.get('stdcode', [''])[0]
    description = vulnerability.get('description', '')
    reported = getTime(vulnerability.get('reported', ''), 'America/Fortaleza')
    consequence = vulnerability.get('consequences', '')
    exploitability = vulnerability.get('exploitability', '')
    platform_affected = vulnerability.get('platforms_affected', [''])[0]

    references = vulnerability.get('references', [])
    cve_links = [ref['link_target'] for ref in references if isCVELink(ref.get('link_target', ''))]

    whatsapp_message = f"*NOVA VULNERABILIDADE*\n\n{title}\n{stdcode}\n{description}\nData (UTC-3): {reported}\nConsequence: {consequence}\nExploitability: {exploitability}\nPlatform Affected: {platform_affected}"

    if cve_links:
        whatsapp_message += "\n\n" + "\n".join(cve_links)

    phones_str  = ",".join(whatsapp_phone_numbers)

    curl_body = f'{{ "messaging_product": "whatsapp", "to": "{phones_str}", "type": "text", "text": {{"preview_url": false, "body": "{whatsapp_message}"}} }}'

    curl_command = f'curl -i -X POST \'https://graph.facebook.com/v18.0/{whatsapp_phone_id}/messages\' -H \'Authorization: Bearer {whatsapp_token}\' -H \'Content-Type: application/json\' -d \'{{ "messaging_product": "whatsapp", "to": "{phones_str}", "type": "text", "text": {{ "preview_url": false, "body": "*IBM X-FORCE: NOVA VULNERABILIDADE*\\n\\n*{title}*\\n\\n_{stdcode}_\\n\\nData UTC-3: {reported}\\n\\nTipo: {consequence}\\n\\nExploitability: {exploitability}\\n\\n{description}\\n\\n{", ".join(cve_links)}" }} }}\''

    print(curl_command)
    subprocess.run(curl_command, shell=True)

