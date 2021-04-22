#!/bin/bash

sudo rm -rf build/ARBITER/*
sudo cp src/* build/ARBITER/ -r
sudo chmod -R 555 build/ARBITER/DEBIAN/postinst
