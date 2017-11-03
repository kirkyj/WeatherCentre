import pymongo

from pymongo import MongoClient

myClient = MongoClient('localhost', 27017)

db = myClient.test_db

wc_1_db = db.wc_1

print (wc_1_db.getIndexes())