import requests
import json 
import datetime
from urllib.parse import quote
import os

xforce_api_key = os.environ.get("XFORCE_API_KEY")

def getAuthToken():

    return f"{xforce_api_key}"

def getNewVulnerabilities():
    url = 'https://api.xforce.ibmcloud.com/api/vulnerabilities/'

    dateToday = datetime.datetime.now(datetime.UTC)
    datePast = dateToday - datetime.timedelta(days=2)

    dateStart = datePast.strftime('%Y-%m-%dT%H:%M:%SZ')
    dateEnd = dateToday.strftime('%Y-%m-%dT%H:%M:%SZ')

    dateStart = quote(dateStart)
    dateEnd = quote(dateEnd)

    parameters = f'?startDate={dateStart}&endDate={dateEnd}'
    url_full = f'{url}{parameters}'

    headers = {
        'accept': 'application/json',
        'Authorization': getAuthToken()
    }

    response = requests.get(url_full, headers=headers)

    if response.status_code == 200:
        json_data = response.json()

        results_folder = 'results'
        if not os.path.exists(results_folder):
            os.makedirs(results_folder)

        timestamp = dateToday.strftime('%d-%m-%Y')
        filename = os.path.join(results_folder, f'vulnerabilidades-{timestamp}.json')

        with open(filename, 'w') as file:
            json.dump(json_data, file, indent=2)

        print(f'Resultado salvo em {filename}')
    elif response.status_code == 404:
        print('Sem vulnerabilidades nas últimas 24 horas')
    else:
        print(f'Erro {response.status_code}: {response.text}')
        print(url_full)

getNewVulnerabilities()
    