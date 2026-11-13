import sqlite3
c = sqlite3.connect("hits.db")
c.executemany("delete from sent where domain=?", [("bing.com",), ("canada.ca",), ("utoronto.ca",), ("sfu.ca",)])
c.commit()
print("sent rows left:", c.execute("select count(*) from sent").fetchone()[0])
