#!/usr/bin/env python

import qicinga2

from unittest import TestCase

class FakeOptions(object):
    def __init__(self):
        self.icinga_url='http://localhost:7717/'
        self.username='user'
        self.password='pass'
        self.showall=True
        self.colour=False
        self.quiet=True

class TestQicinga(TestCase):

    def test_loadjson(self):
        with open ("testout.json", "r") as myfile:
            data=myfile.read()
        json = qicinga2.read_json(data)
        return json

    def test_parsechecks(self):
        json = self.test_loadjson()
        opts = FakeOptions()
        qicinga2.parse_checks(json, opts)
