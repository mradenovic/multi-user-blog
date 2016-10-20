"""Udacity Project: Multi User Blog"""

import webapp2

from handlers import BlogFront
from handlers import PostView
from handlers import PostEdit
from handlers import PostDelete
from handlers import PostCreate
from handlers import PostLike
from handlers import PostComment
from handlers import CommentEdit
from handlers import CommentDelete
from handlers import Register
from handlers import Login
from handlers import Logout
from handlers import Welcome

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
