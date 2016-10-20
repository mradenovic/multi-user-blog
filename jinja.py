"""Helpers for rendering jinja2 templates"""

import os
import jinja2


template_dir = os.path.join(os.path.dirname(__file__), 'templates')
jinja_env = jinja2.Environment(loader=jinja2.FileSystemLoader(template_dir),
                               autoescape=True)


def render_str(template, **params):
    template = jinja_env.get_template(template)
    return template.render(params)
