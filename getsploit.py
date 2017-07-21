#!/usr/bin/env python3.6

import argparse
import json
import os
import os.path
import re
import sqlite3
import ssl
import sys
import urllib.parse
import urllib.request
import zipfile

import texttable

VULNERS_URL = {
    'searchAPI': 'https://vulners.com/api/v3/search/lucene/',
    'updateAPI': 'https://vulners.com/api/v3/archive/getsploit/',
    'idAPI': 'https://vulners.com/api/v3/search/id/',
}
DBPATH, SCRIPTNAME = os.path.split(os.path.abspath(__file__))
DBFILE = os.path.join(DBPATH, 'getsploit.db')


def slugify(value):
    """
    Normalizes string, converts to lowercase, removes non-alpha characters,
    and converts spaces to hyphens.
    """
    value = re.sub('[^\w\s-]', '', value).strip().lower()
    value = re.sub('[-\s]+', '-', value)
    return value


def progress_callback_simple(downloaded, total):
    sys.stdout.write(
        "\r" +
        (len(str(total)) - len(str(downloaded))) * " " + str(downloaded) + "/%d" % total +
        " [%3.2f%%]" % (100.0 * float(downloaded) / float(total))
    )
    sys.stdout.flush()


def downloadFile(srcurl, dstfilepath, progress_callback=None, block_size=8192):
    def _download_helper(response, out_file, file_size):
        if progress_callback!=None: progress_callback(0,file_size)
        if block_size == None:
            buffer = response.read()
            out_file.write(buffer)
            if progress_callback!=None: progress_callback(file_size,file_size)
        else:
            file_size_dl = 0
            while True:
                buffer = response.read(block_size)
                if not buffer: break
                file_size_dl += len(buffer)
                out_file.write(buffer)
                if progress_callback!=None: progress_callback(file_size_dl,file_size)
    with open(dstfilepath,"wb") as out_file:
        opener = getUrllibOpener()
        req = urllib.request.Request(srcurl)
        with opener.open(req) as response:
            file_size = int(response.getheader("Content-Length"))
            _download_helper(response,out_file,file_size)


def getUrllibOpener():
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    opener = urllib.request.build_opener(urllib.request.HTTPSHandler(context=ctx))
    opener.addheaders = [('Content-Type', 'application/json'),('User-Agent', 'vulners-getsploit-v0.2.1')]
    return opener


def searchVulnersQuery(searchQuery, limit):
    vulnersSearchRequest = {"query":searchQuery, 'skip':0, 'size':limit}
    req = urllib.request.Request(VULNERS_URL['searchAPI'])
    response = getUrllibOpener().open(req, json.dumps(vulnersSearchRequest).encode('utf-8'))
    responseData = response.read()
    if isinstance(responseData, bytes):
        responseData = responseData.decode('utf8')
    responseData = json.loads(responseData)
    return responseData


def downloadVulnersGetsploitDB(path):
    archiveFileName = os.path.join(path, 'getsploit.db.zip')
    print("Downloading getsploit database archive. Please wait, it may take time. Usually around 5-10 minutes.")
    downloadFile(VULNERS_URL['updateAPI'], archiveFileName, progress_callback=progress_callback_simple)
    print("\nUnpacking database.")
    zip_ref = zipfile.ZipFile(archiveFileName, 'r')
    zip_ref.extractall(DBPATH)
    zip_ref.close()
    os.remove(archiveFileName)
    return True


def exploitSearch(query, lookupFields=None, limit=10):
    # Build query
    if lookupFields:
        searchQuery = "bulletinFamily:exploit AND (%s)" % " OR ".join("%s:\"%s\"" % (lField, query) for lField in lookupFields)
    else:
        searchQuery = "bulletinFamily:exploit AND %s" % query
    searchResults = searchVulnersQuery(searchQuery, limit).get('data')
    return searchQuery, searchResults


def exploitLocalSearch(query, lookupFields=None, limit=10):
    # Build query
    # CREATE VIRTUAL TABLE exploits USING FTS4(id text, title text, published DATE, description text, sourceData text, vhref text)
    sqliteConnection = sqlite3.connect(DBFILE)
    cursor = sqliteConnection.cursor()
    # Check if FTS4 is supported
    ftsok = False
    for (val,) in cursor.execute('pragma compile_options'):
        if ('FTS4' in val) or ('FTS3' in val):
            ftsok = True
    if not ftsok:
        print("Your SQLite3 library does not support FTS4. Sorry, without this option local search will not work. Recompile SQLite3 with ENABLE_FTS4 option.")
        exit()
    preparedQuery = " AND ".join(['"%s"' % word for word in query.split()])
    searchRawResults = cursor.execute("SELECT * FROM exploits WHERE exploits MATCH ? ORDER BY published LIMIT ?", ('%s' % preparedQuery,limit)).fetchall()
    searchCount = cursor.execute("SELECT Count(*) FROM exploits WHERE exploits MATCH ? ORDER BY published LIMIT ?", ('%s' % preparedQuery,limit)).fetchone()
    searchResults = {'total':searchCount,'search':[]}
    for element in searchRawResults:
        searchResults['search'].append({'_source':
                                               {'id':element[0],
                                                'title':element[1],
                                                'published':element[2],
                                                'description':element[3],
                                                'sourceData':element[4],
                                                'vhref':element[5],
                                                }
                                        })
    # Output must b
    return query, searchResults


def main():
    parser = argparse.ArgumentParser(description="Exploit search and download utility")
    parser.add_argument("query", type=str, help="Exploit search query. See https://vulners.com/help for the detailed manual.")
    parser.add_argument("-t", "--title", action="store_true", help="Search JUST the exploit title (Default is description and source code).")
    parser.add_argument("-j", "--json", action="store_true", help="Show result in JSON format.")
    parser.add_argument("-m", "--mirror", action="store_true", help="Mirror (aka copies) search result exploit files to the subdirectory with your search query name.")
    parser.add_argument("-c", "--count", default=10, type=int, help="Search limit. Default 10.")
    parser.add_argument("-l", "--local", action="store_true", help="Perform search in the local database instead of searching online.")
    parser.add_argument("-u", "--update", action="store_true", help="Update getsploit.db database. Will be downloaded in the script path.")
    args = parser.parse_args()

    if args.update:
        downloadVulnersGetsploitDB(DBPATH)
        print("Database download complete. Now you may search exploits using --local key './getsploit.py -l wordpress 4.7'")
        exit()

    if args.local:
        if not os.path.exists(DBFILE):
            print("There is no local database file near getsploit. Run './getsploit.py --update'")
            exit()
        finalQuery, searchResults = exploitLocalSearch(args.query, lookupFields=['title'] if args.title else None, limit = args.count)
    else:
        finalQuery, searchResults = exploitSearch(args.query, lookupFields=['title'] if args.title else None, limit = args.count)

    outputTable = texttable.Texttable()
    outputTable.set_cols_dtype(['t', 't', 't'])
    outputTable.set_cols_align(['c', 'l', 'c'])
    outputTable.set_cols_width(['20', '30', '100'])
    tableRows = [['ID', 'Exploit Title', 'URL']]
    jsonRows = []
    for bulletinSource in searchResults.get('search'):
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
        print("Total found exploits: %s" % searchResults.get('total'))
        quoteStringHandler = urllib.parse.quote_plus
        print("Web-search URL: https://vulners.com/search?query=%s" % quoteStringHandler(finalQuery))
        # Set max coll width by len of the url for better copypaste
        maxWidth = max(len(element[2]) for element in tableRows)
        outputTable.set_cols_width([20, 30, maxWidth])
        outputTable.add_rows(tableRows)
        print(outputTable.draw())


if __name__ == '__main__':
    main()
