#!/usr/bin/env python

import yaml
from collections import OrderedDict

def load(obj):
    if type(obj) == file:
        return load_stream(obj)
        
    with open(obj, 'r') as fh:
        return load_stream(fh, yaml.SafeLoader)


def load_stream(stream, Loader=yaml.Loader, object_pairs_hook=OrderedDict):
    class OrderedLoader(Loader):
        pass
    def construct_mapping(loader, node):
        loader.flatten_mapping(node)
        return object_pairs_hook(loader.construct_pairs(node))
    OrderedLoader.add_constructor(
        yaml.resolver.BaseResolver.DEFAULT_MAPPING_TAG,
        construct_mapping)

    return yaml.load(stream, OrderedLoader)

