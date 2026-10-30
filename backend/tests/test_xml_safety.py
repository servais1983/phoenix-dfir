"""Evidence XML is untrusted: DTDs and entity expansion are refused."""

import xml.etree.ElementTree as ET

import pytest

import parsers

BOMB = ('<?xml version="1.0"?><!DOCTYPE lolz [<!ENTITY lol "lol">'
        '<!ENTITY lol2 "&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;">]><r>&lol2;</r>')


def test_entity_expansion_is_refused():
    with pytest.raises((ET.ParseError, ValueError)):
        parsers.xml_fromstring(BOMB)


def test_fallback_without_defusedxml_also_refuses(monkeypatch):
    monkeypatch.setattr(parsers, '_defused_fromstring', None)
    with pytest.raises(ET.ParseError):
        parsers.xml_fromstring(BOMB)


def test_plain_event_xml_still_parses():
    root = parsers.xml_fromstring('<Event><System><EventID>4624</EventID></System></Event>')
    assert root.find('System/EventID').text == '4624'
