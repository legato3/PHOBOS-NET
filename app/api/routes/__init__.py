from flask import Blueprint

# Combined Blueprint for all decomposed routes
bp = Blueprint("routes", __name__)

# Import routes to register them with the blueprint
# These imports happen after bp is defined to avoid circular dependency
from . import system
from . import traffic
from . import security
from . import timeline
from . import events
from . import pulse
