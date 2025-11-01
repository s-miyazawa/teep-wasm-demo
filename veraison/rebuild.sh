#!/bin/bash
rm services/scheme/bin/generic-eat.plugin
veraison stop
make -C services native-deploy
veraison start
