"""Udacity Project: Multi User Blog"""

import webapp2

from lib.handlers import BlogFront
from lib.handlers import PostView
from lib.handlers import PostEdit
from lib.handlers import PostDelete
from lib.handlers import PostCreate
from lib.handlers import PostLike
from lib.handlers import PostComment
from lib.handlers import CommentEdit
from lib.handlers import CommentDelete
from lib.handlers import Register
from lib.handlers import Login
from lib.handlers import Logout
from lib.handlers import Welcome

app = webapp2.WSGIApplication([('/?', BlogFront),
                               ('/post/(view)/([0-9]+)', PostView),
                               ('/post/(edit)/([0-9]+)', PostEdit),
                               ('/post/(delete)/([0-9]+)', PostDelete),
                               ('/post/(create)/()', PostCreate),
                               ('/post/(like)/([0-9]+)', PostLike),
                               ('/post/(comment)/([0-9]+)', PostComment),
                               ('/comment/(edit)/([0-9]+)', CommentEdit),
                               ('/comment/(delete)/([0-9]+)', CommentDelete),
                               ('/signup', Register),
                               ('/login', Login),
                               ('/logout', Logout),
                               ('/welcome', Welcome)],
                              debug=True)
