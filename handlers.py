"""Blog handlers"""
from validators import valid_username
from validators import valid_password
from validators import valid_email

import webapp2

from google.appengine.ext import db
from models import User, Post, Comment, Like
from jinja import render_str
from encrypt import make_secure_val, check_secure_val


class BlogHandler(webapp2.RequestHandler):
    """Class for handling common Blog tasks"""
    user = None

    def write(self, *a, **kw):
        self.response.out.write(*a, **kw)

    def render_str(self, template, **params):
        params['user'] = self.user
        return render_str(template, **params)

    def render(self, template, **kw):
        self.write(self.render_str(template, **kw))

    def set_secure_cookie(self, name, val):
        cookie_val = make_secure_val(val)
        self.response.headers.add_header(
            'Set-Cookie',
            '%s=%s; Path=/' % (name, cookie_val))

    def read_secure_cookie(self, name):
        cookie_val = self.request.cookies.get(name)
        return cookie_val and check_secure_val(cookie_val)

    def login(self, user):
        self.set_secure_cookie('user_id', str(user.key().id()))

    def logout(self):
        self.response.headers.add_header('Set-Cookie', 'user_id=; Path=/')

    def initialize(self, *a, **kw):
        webapp2.RequestHandler.initialize(self, *a, **kw)
        uid = self.read_secure_cookie('user_id')
        self.user = uid and User.by_id(int(uid))


def render_post(response, post):
    response.out.write('<b>' + post.subject + '</b><br>')
    response.out.write(post.content)


# blog stuff


class BlogFront(BlogHandler):

    def get(self):
        posts = Post.all().order('-created')
        self.render('front.html', posts=posts)


class PostPermission(object):
    """Class to augument post handling classes"""
    blog_post = None
    user_is_post_owner = None
    like = None
    message = None
    params = {}

    def init_env(self, action, entity_id):
        if action in ['view', 'edit', 'delete', 'like']:
            self.blog_post = Post.by_id(entity_id)
            if self.blog_post:
                self.user_is_post_owner = self.user and self.user.key(
                ) == self.blog_post.created_by.key()
                self.like = self.user and Like.gql(
                    'WHERE post = :post AND liked_by = :user',
                    post=self.blog_post.key(),
                    user=self.user.key()).get()

    def validate(self, action, entity_id):
        """Validate if action is permited on entity"""
        self.init_env(action, entity_id)
        if not self.blog_post and action not in ['create']:
            self.write('There is no entity with id %s' % entity_id)
            return False
        elif not self.user and action not in ['view']:
            self.redirect('/login')
            return False
        elif action in ['edit', 'delete'] and not self.user_is_post_owner:
            self.message = 'you can %s only your own post!' % action
            return False
        elif action in ['like'] and self.user_is_post_owner:
            self.message = 'you can not %s your own post!' % action
            return False
        elif action in ['like'] and self.like:
            self.message = 'you can %s any post only once!' % action
            return False
        return True


class PostView(BlogHandler, PostPermission):

    def get(self, action, post_id):
        if self.validate(action, post_id):
            self.render('permalink.html', post=self.blog_post)


class PostDelete(BlogHandler, PostPermission):

    def get(self, action, post_id):
        if self.validate(action, post_id):
            for comment in self.blog_post.comment_set:
                comment.delete()
            self.blog_post.delete()
            self.redirect('/')
        else:
            params = {}
            params['post'] = self.blog_post
            params['edit_error'] = self.message
            self.render('permalink.html', **params)


class PostCreate(BlogHandler, PostPermission):

    def get(self, action, post_id):
        if self.validate(action, post_id):
            self.render("post-form.html", action=action)

    def post(self, action, post_id):
        """Create new blog post or edit existing one"""
        if self.validate(action, post_id):
            subject = self.request.get('subject')
            content = self.request.get('content')

            self.upsert_blog_post(subject, content)
        else:
            params = {}
            params['post'] = self.blog_post
            params['edit_error'] = self.message
            self.render('permalink.html', **params)

    def upsert_blog_post(self, subject, content):
        """Update or insert(crate) blog post."""
        if subject and content:
            if not self.blog_post:
                self.blog_post = Post(
                    subject=subject, content=content, created_by=self.user)
            else:
                self.blog_post.subject = subject
                self.blog_post.content = content
            self.blog_post.put()
            self.redirect('/post/view/%s' % str(self.blog_post.key().id()))
        else:
            error = "subject and content, please!"
            self.render("post-form.html", subject=subject,
                        content=content, error=error)


class PostEdit(PostCreate):

    def get(self, action, post_id):
        if self.validate(action, post_id):
            params = {}
            params['subject'] = self.blog_post.subject
            params['content'] = self.blog_post.content
            params['action'] = action
            params['post_id'] = post_id
            self.render('post-form.html', **params)
        else:
            params = {}
            params['post'] = self.blog_post
            params['edit_error'] = self.message
            self.render('permalink.html', **params)


class PostLike(BlogHandler, PostPermission):

    def get(self, action, post_id):
        if self.validate(action, post_id):
            params = {}
            like = Like(post=self.blog_post, liked_by=self.user)
            key = like.put()
            # get updated object
            params['post'] = db.get(key).post
            self.render("permalink.html", **params)
        else:
            params = {}
            params['post'] = self.blog_post
            params['edit_error'] = self.message
            self.render('permalink.html', **params)


class CommentPermission(object):
    """Class to augument comment handling classes"""
    comment = None
    blog_post = None
    user_is_comment_owner = None
    message = None
    params = {}

    def init_env(self, action, entity_id):
        if action in ['comment']:
            self.blog_post = Post.by_id(entity_id)
        elif action in ['edit', 'delete']:
            self.comment = Comment.by_id(entity_id)
            if self.comment:
                self.user_is_comment_owner = self.user and self.user.key(
                ) == self.comment.created_by.key()
                self.blog_post = self.comment.post

    def validate(self, action, entity_id):
        """Validate if action is permited on entity"""
        self.init_env(action, entity_id)
        if not self.blog_post or (action in ['edit', 'delete'] and not self.comment):
            self.write('There is no entity with id %s' % entity_id)
            return False
        elif not self.user:
            self.message = 'Only logged in users can %s!' % action
        elif action in ['edit', 'delete'] and not self.user_is_comment_owner:
            self.message = 'You can %s only your own comment!' % action
        return True


class PostComment(BlogHandler, CommentPermission):

    def get(self, action, post_id):
        if self.validate(action, post_id):
            params = {}
            if self.message:
                params['comment_action_error'] = self.message
            else:
                params['action'] = action
            params['post'] = self.blog_post
            self.render("permalink.html", **params)

    def post(self, action, post_id):
        """Create new commentor edit existing one"""
        if self.validate(action, post_id):
            content = self.request.get('content')

            if content:
                if self.comment:
                    self.comment.content = content
                else:
                    self.create_comment(content)
                key = self.comment.put()
                # get updated object
                self.blog_post = db.get(key).post
                error = ''
            else:
                error = "content, please!"
            self.render("permalink.html", post=self.blog_post, error=error)

    def create_comment(self, content):
        params = {}
        params['content'] = content
        params['post'] = self.blog_post
        params['created_by'] = self.user
        self.comment = Comment(**params)


class CommentEdit(PostComment):

    def get(self, action, comment_id):
        if self.validate(action, comment_id):
            params = {}
            if self.message:
                params['comment_action_error'] = self.message
            else:
                params['action'] = action
                params['content'] = self.comment.content
                params['post_id'] = self.blog_post.key().id()
            params['post'] = self.blog_post
            self.render("permalink.html", **params)


class CommentDelete(BlogHandler, CommentPermission):

    def get(self, action, comment_id):
        if self.validate(action, comment_id):
            params = {}
            if self.message:
                params['comment_action_error'] = self.message
            else:
                self.comment.delete()
            params['post'] = self.blog_post
            self.render("permalink.html", **params)


# Unit 2 HW's
class Signup(BlogHandler):
    """Class for nadling signup tasks"""
    username = None
    password = None
    verify = None
    email = None

    def get(self):
        self.render("signup-form.html")

    def post(self):
        """Post signup data"""
        have_error = False
        self.username = self.request.get('username')
        self.password = self.request.get('password')
        self.verify = self.request.get('verify')
        self.email = self.request.get('email')

        params = dict(username=self.username,
                      email=self.email)

        if not valid_username(self.username):
            params['error_username'] = "That's not a valid username."
            have_error = True

        if not valid_password(self.password):
            params['error_password'] = "That wasn't a valid password."
            have_error = True
        elif self.password != self.verify:
            params['error_verify'] = "Your passwords didn't match."
            have_error = True

        if not valid_email(self.email):
            params['error_email'] = "That's not a valid email."
            have_error = True

        if have_error:
            self.render('signup-form.html', **params)
        else:
            self.done()

    def done(self, *a, **kw):
        raise NotImplementedError


class Register(Signup):

    def done(self):
        # make sure the user doesn't already exist
        u = User.by_name(self.username)
        if u:
            msg = 'That user already exists.'
            self.render('signup-form.html', error_username=msg)
        else:
            u = User.register(self.username, self.password, self.email)
            u.put()

            self.login(u)
            self.redirect('/')


class Login(BlogHandler):

    def get(self):
        self.render('login-form.html')

    def post(self):
        username = self.request.get('username')
        password = self.request.get('password')

        user = User.login(username, password)
        if user:
            self.login(user)
            self.redirect('/')
        else:
            msg = 'Invalid login'
            self.render('login-form.html', error=msg)


class Logout(BlogHandler):

    def get(self):
        self.logout()
        self.redirect('/')


class Welcome(BlogHandler):

    def get(self):
        if self.user:
            self.render('welcome.html', username=self.user.name)
        else:
            self.redirect('/signup')
