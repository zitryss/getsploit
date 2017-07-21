#!/usr/bin/env python3.6

import argparse

import requests
import texttable


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
    parser.add_argument("-c", "--count", default=10, type=int, help="Search limit. Default 10.")
    args = parser.parse_args()
    search_results = search_exploit(args)
    output_table = texttable.Texttable()
    output_table.set_cols_dtype(['t', 't', 't'])
    output_table.set_cols_align(['c', 'l', 'c'])
    output_table.set_cols_width(['20', '30', '100'])
    table_rows = [['ID', 'Exploit Title', 'URL']]
    for bulletinSource in search_results.get("search"):
        bulletin = bulletinSource.get('_source')
        bulletin_url = bulletin.get('vref') or 'https://vulners.com/%s/%s' % (bulletin.get('type'), bulletin.get('id'))
        table_rows.append([bulletin.get('id'), bulletin.get('title'), bulletin_url])
    print("Total found exploits: %s" % search_results.get('total'))
    max_width = max(len(element[2]) for element in table_rows)
    output_table.set_cols_width([20, 30, max_width])
    output_table.add_rows(table_rows)
    print(output_table.draw())


if __name__ == '__main__':
    main()
