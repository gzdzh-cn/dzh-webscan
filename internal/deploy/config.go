package deploy

import configuration "webscan/internal/config"

type Config = configuration.Config

var Load = configuration.Load
var Redact = configuration.Redact
var validPath = configuration.ValidPath
