#!/usr/bin/env python3.6

import argparse
import json
import os
import os.path
import re

import requests
import texttable


def slugify(value):
    """
    Normalizes string, converts to lowercase, removes non-alpha characters,
    and converts spaces to hyphens.
    """
    value = re.sub('[^\w\s-]', '', value).strip().lower()
    value = re.sub('[-\s]+', '-', value)
    return value


def receive_data(search_query, count):
    vulners_search_request = {
        "query": search_query,
        "skip": 0,
        "size": count,
    }
    response = requests.get("https://vulners.com/api/v3/search/lucene/", vulners_search_request)
    return response.json()


def search_exploit(args):
    if args.title:
        search_query = f"bulletinFamily:exploit AND (title:\"{args.query}\")"
    else:
        search_query = f"bulletinFamily:exploit AND {args.query}"
    search_results = receive_data(search_query, args.count)
    return search_results.get("data")


def main():
    parser = argparse.ArgumentParser(description="Exploit search and download utility")
    parser.add_argument("query", type=str, help="Exploit search query. See https://vulners.com/help for the detailed manual.")
    parser.add_argument("-t", "--title", action="store_true", help="Search JUST the exploit title (Default is description and source code).")
    parser.add_argument("-j", "--json", action="store_true", help="Show result in JSON format.")
    parser.add_argument("-m", "--mirror", action="store_true", help="Mirror (aka copies) search result exploit files to the subdirectory with your search query name.")
    parser.add_argument("-c", "--count", default=10, type=int, help="Search limit. Default 10.")
    args = parser.parse_args()
    search_results = search_exploit(args)
    outputTable = texttable.Texttable()
    outputTable.set_cols_dtype(['t', 't', 't'])
    outputTable.set_cols_align(['c', 'l', 'c'])
    outputTable.set_cols_width(['20', '30', '100'])
    tableRows = [['ID', 'Exploit Title', 'URL']]
    jsonRows = []
    for bulletinSource in search_results.get("search"):
        bulletin = bulletinSource.get('_source')
        bulletinUrl = bulletin.get('vref') or 'https://vulners.com/%s/%s' % (bulletin.get('type'), bulletin.get('id'))
        tableRows.append([bulletin.get('id'), bulletin.get('title'), bulletinUrl])
        if args.json:
            jsonRows.append({'id':bulletin.get('id'), 'title':bulletin.get('title'), 'url':bulletinUrl})
        if args.mirror:
            pathName = './%s' % slugify(args.query)
            # Put results it the dir
            if not os.path.exists(pathName):
                os.mkdir(pathName)
            with open("./%s/%s.txt" % (pathName,slugify(bulletin.get('id'))), 'w') as exploitFile:
                exploitData = bulletin.get('sourceData') or bulletin.get('description')
                exploitFile.write(exploitData)
    if args.json:
        # Json output
        print(json.dumps(jsonRows))
    else:
        # Text output
        print("Total found exploits: %s" % search_results.get('total'))
        # Set max coll width by len of the url for better copypaste
        maxWidth = max(len(element[2]) for element in tableRows)
        outputTable.set_cols_width([20, 30, maxWidth])
        outputTable.add_rows(tableRows)
        print(outputTable.draw())


if __name__ == '__main__':
    main()
