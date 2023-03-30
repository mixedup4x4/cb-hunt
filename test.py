import logging as l

l.basicConfig(level=l.INFO,format="%(asctime)s [%(levelname)s] %(message)s",handlers=[l.FileHandler("debug.log"),cat 
                                                                                      l.StreamHandler()])

l.info("test")

