from jose import jwt


def getClaim(token, claim_name):

    claims = jwt.get_unverified_claims(token)

    return claims[claim_name]