from __future__ import division  # Use floating point for math calculations

import math
import requests

from flask import Blueprint

from CTFd.models import Challenges, Solves, db
from CTFd.plugins import register_plugin_assets_directory
from CTFd.plugins.challenges import CHALLENGE_CLASSES, BaseChallenge
from CTFd.plugins.migrations import upgrade
from CTFd.utils.modes import get_model
from CTFd.utils import user as current_user

class CryptohackChallengeModel(Challenges):
    __mapper_args__ = {"polymorphic_identity": "cryptohack"}
    id = db.Column(
        db.Integer, db.ForeignKey("challenges.id", ondelete="CASCADE"), primary_key=True
    )
    initial = db.Column(db.Integer, default=0) # How much each level is worth
    minimum = db.Column(db.Integer, default=0) # Maximum points for this challenge
    decay = db.Column(db.Integer, default=0) # Levels till maximum is reached

    def __init__(self, *args, **kwargs):
        super(CryptohackChallengeModel, self).__init__(**kwargs)
        self.value = kwargs["initial"]

class CryptohackChallenge(BaseChallenge):
    id = "cryptohack"  # Unique identifier used to register challenges
    name = "cryptohack"  # Name of a challenge type

    templates = {  # Handlebars templates used for each aspect of challenge editing & viewing
        "create": "/plugins/cryptohack_challenges/assets/create.html",
        "update": "/plugins/cryptohack_challenges/assets/update.html",
        "view": "/plugins/cryptohack_challenges/assets/view.html",
    }
    scripts = {  # Scripts that are loaded when a template is loaded
        "create": "/plugins/cryptohack_challenges/assets/create.js",
        "update": "/plugins/cryptohack_challenges/assets/update.js",
        "view": "/plugins/cryptohack_challenges/assets/view.js",
    }
    # Route at which files are accessible. This must be registered using register_plugin_assets_directory()
    route = "/plugins/cryptohack_challenges/assets/"
    # Blueprint used to access the static_folder directory.
    blueprint = Blueprint(
        "cryptohack_challenges",
        __name__,
        template_folder="templates",
        static_folder="assets",
    )
    challenge_model = CryptohackChallengeModel
    cryptohack_challenge_format = "Cryptohack Level "

    @classmethod
    def attempt(cls, challenge, request):

        data = request.form or request.get_json()
        submission = data["submission"].split('!connect ')[-1].strip()

        print(submission)
        res = requests.get(f'https://cryptohack.org/discord_token/{submission}/')

        if res.status_code != 200:
            return False, "Error"
        res = res.json()
        if 'error' in res:
            return False, res['error']
        user = res['user']
        res = requests.get(f'https://cryptohack.org/api/user/{user}/')

        if res.status_code != 200:
            return False, "Error"
        res = res.json()
        if 'error' in res:
            return False, res['error']
        current_level = res['level']

        # Get all cryptohack challenges
        challenges_to_update = Challenges.query.filter_by(category=challenge.category).all()

        highest_level = 0
        challenge_solve_map = {}
        for chal in challenges_to_update:
            if chal.name.startswith(cls.cryptohack_challenge_format):
                level = int(chal.name[len(cls.cryptohack_challenge_format):])
                if level > highest_level:
                    highest_level = level
                challenge_solve_map[level] = chal.id
        # Create required cryptohack challenges
        
        for level in range(highest_level + 1, current_level + 1):
            new_chal = Challenges(
                name=cls.cryptohack_challenge_format + str(level),
                description="",
                value=cls.calculate_level_value(challenge, level),
                category=challenge.category,
                type="standard",
                requirements={'prerequisites': [] if level == 1 else [challenge_solve_map[level - 1]]},
                state="visible"
            )
            db.session.add(new_chal)
            db.session.commit()
            challenge_solve_map[level] = new_chal.id
        # Generate solves
        user = current_user.get_current_user()

        for level in range(1, current_level + 1):
            solved = Solves.query.filter_by(challenge_id=challenge_solve_map[level], user_id=user.id).all()
            if len(solved) == 0:
                solve = Solves(challenge_id=challenge_solve_map[level], 
                    user_id=user.id,
                    team_id=user.team_id)
                db.session.add(solve)
                db.session.commit()

        return False, "Successfully Awarded Points!"
    @classmethod
    def read(cls, challenge):
        """
        This method is in used to access the data of a challenge in a format processable by the front end.

        :param challenge:
        :return: Challenge object, data dictionary to be returned to the user
        """
        challenge = CryptohackChallengeModel.query.filter_by(id=challenge.id).first()
        data = {
            "id": challenge.id,
            "name": challenge.name,
            "value": challenge.value,
            "initial": challenge.initial,
            "decay": challenge.decay,
            "minimum": challenge.minimum,
            "description": challenge.description,
            "connection_info": challenge.connection_info,
            "category": challenge.category,
            "state": challenge.state,
            "max_attempts": challenge.max_attempts,
            "type": challenge.type,
            "type_data": {
                "id": cls.id,
                "name": cls.name,
                "templates": cls.templates,
                "scripts": cls.scripts,
            },
        }
        return data

    @staticmethod
    def calculate_level_value(challenge, level):
        return min(challenge.minimum, challenge.initial + level * challenge.decay)
    @classmethod
    def update(cls, challenge, request):
        """
        This method is used to update the information associated with a challenge. This should be kept strictly to the
        Challenges table and any child tables.

        :param challenge:
        :param request:
        :return:
        """
        data = request.form or request.get_json()

        old_category = challenge.category
        for attr, value in data.items():
            # We need to set these to floats so that the next operations don't operate on strings
            if attr in ("initial", "minimum", "decay"):
                value = float(value)
            setattr(challenge, attr, value)

        # Move the category of other CryptoHack challenges and update the points
        challenges_to_update = Challenges.query.filter_by(category=old_category).all()
        for chal in challenges_to_update:
            if chal.name.startswith(cls.cryptohack_challenge_format):
                level = int(chal.name[len(cls.cryptohack_challenge_format) :])
                chal.value = cls.calculate_level_value(challenge, level)
            chal.category = challenge.category
        
        db.session.commit()
        return challenge

    @classmethod
    def solve(cls, user, team, challenge, request):
        super().solve(user, team, challenge, request)

        CryptohackChallenge.calculate_value(challenge)


def load(app):
    upgrade(plugin_name="cryptohack_challenges")
    app.db.create_all()
    CHALLENGE_CLASSES["cryptohack"] = CryptohackChallenge
    register_plugin_assets_directory(
        app, base_path="/plugins/cryptohack_challenges/assets/"
    )
