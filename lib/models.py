"""Models for the Google app engine datastore"""

from encrypt import make_pw_hash
from encrypt import valid_pw
from jinja import render_str

from google.appengine.ext import db


def users_key(group='default'):
    return db.Key.from_path('users', group)


class User(db.Model):
    """User model"""

    name = db.StringProperty(required=True)
    pw_hash = db.StringProperty(required=True)
    email = db.StringProperty()

    @classmethod
    def by_id(cls, uid):
        return User.get_by_id(uid, parent=users_key())

    @classmethod
    def by_name(cls, name):
        user = User.all().filter('name =', name).get()
        return user

    @classmethod
    def register(cls, name, pw, email=None):
        pw_hash = make_pw_hash(name, pw)
        return User(parent=users_key(),
                    name=name,
                    pw_hash=pw_hash,
                    email=email)

    @classmethod
    def login(cls, name, pw):
        user = cls.by_name(name)
        if user and valid_pw(name, pw, user.pw_hash):
            return user


class BlogModel(db.Model):
    """Base model class """

    @classmethod
    def by_id(cls, model_id):
        return cls.get_by_id(int(model_id))


class Post(BlogModel):
    """Post model"""

    subject = db.StringProperty(required=True)
    content = db.TextProperty(required=True)
    created_by = db.ReferenceProperty(User, required=True)
    created = db.DateTimeProperty(auto_now_add=True)
    last_modified = db.DateTimeProperty(auto_now=True)
    _render_text = None

    def render(self):
        self._render_text = self.content.replace('\n', '<br>')
        return render_str("post.html", p=self)


class Like(BlogModel):
    """Like model"""

    post = db.ReferenceProperty(Post, required=True)
    liked_by = db.ReferenceProperty(User, required=True)
    created = db.DateTimeProperty(auto_now_add=True)
    last_modified = db.DateTimeProperty(auto_now=True)


class Comment(BlogModel):
    """Comment model"""
    
    content = db.TextProperty(required=True)
    post = db.ReferenceProperty(Post, required=True)
    created_by = db.ReferenceProperty(User, required=True)
    created = db.DateTimeProperty(auto_now_add=True)
    last_modified = db.DateTimeProperty(auto_now=True)
    _render_text = None

    def render(self):
        self._render_text = self.content.replace('\n', '<br>')
        return render_str("comment.html", comment=self)
