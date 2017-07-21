#!/usr/bin/env python3.6

import argparse
import sys

import requests
import texttable


def main():
    if sys.version_info < (3, 6):
        raise SystemExit("Python version 3.6 or later is required!")
    search_exploits()
    sys.exit()


def search_exploits():
    args = parse_arguments()
    json = receive_json(args)
    data = extract_data(json)
    table = create_table(data)
    print_results(json, table)


def parse_arguments():
    parser = argparse.ArgumentParser(description="Exploit search utility.")
    parser.add_argument("query", type=str)
    parser.add_argument("-t", "--title", action="store_true",
                        help="search only in the exploit title "
                             "(default: description and source code)")
    parser.add_argument("-c", "--count", default=10, type=int, metavar="N",
                        help="search limit (default: 10)")
    return parser.parse_args()


def receive_json(args):
    url = "https://vulners.com/api/v3/search/lucene/"
    params = {
        "query": define_search_query(args),
        "skip": 0,
        "size": args.count,
    }
    response = requests.get(url, params)
    return response.json()


def define_search_query(args):
    if args.title:
        search_query = f"bulletinFamily:exploit AND (title:\"{args.query}\")"
    else:
        search_query = f"bulletinFamily:exploit AND {args.query}"
    return search_query


def extract_data(json):
    search_results = json["data"]["search"]
    data = [["ID", "Exploit Title", "URL"]]
    for entry in search_results:
        id_ = entry["_source"]["id"]
        title = entry["_source"]["title"]
        type_ = entry["_source"]["type"]
        url = f"https://vulners.com/{type_}/{id_}"
        data.append([id_, title, url])
    return data


def create_table(data):
    table = texttable.Texttable()
    table.set_cols_align(["c", "l", "c"])
    third_column_width = calculate_column_width(data, column=3)
    table.set_cols_width([20, 30, third_column_width])
    table.add_rows(data)
    return table


def calculate_column_width(data, column):
    return max(len(each[column-1]) for each in data)


def print_results(json, table):
    print(f"Total exploits found: {count_search_results(json)}")
    print(table.draw())


def count_search_results(json):
    return json["data"]["total"]


if __name__ == "__main__":
    main()
