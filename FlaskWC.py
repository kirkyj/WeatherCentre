from flask import Flask, render_template
from pymongo import MongoClient
from collections import Counter
from flask import Markup

app = Flask(__name__)

@app.route("/")
def show_home():

    entries = main()
    sorted_entries = sorted(entries.items(), key=lambda x: x[1])

    for entry in sorted_entries:
        if entry[1] <= 10:
            # Increment an 'other' count
            # Pop the record from the list but store it so it could be shown in a drill-down page
    return render_template('home.html', entries=sorted_entries)

@app.route("/chart")
def show_chart():

    entries = main()
    sorted_entries = sorted(entries.items(), key=lambda x: x[1])
    data = []

    for entry in sorted_entries:
        if entry[1] >= 10:
            data.append(entry)

    return render_template('chart.html', entries=data)

def main():
    from collections import Counter

    myClient = MongoClient('localhost', 27017)

    db = myClient.test_db

    wc_1_db = db.wc_1

    counts = []
    servers = []

    for totals in wc_1_db.find({}, {"name_servers.ns_provider": 1}):
        # print (totals["name_servers"])
        for ns in totals["name_servers"]:
            servers.append(ns["ns_provider"])

        unique = list(set(servers))
        for provider in unique:
            counts.append(provider)
        servers.clear()

    converted = list(counts)
    output = dict(Counter(converted))

    #print (dict(output))

    return output

