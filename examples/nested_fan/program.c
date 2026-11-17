signed char limit_speed(signed char requested, signed char limit)
{
    if (requested < 0)
        return 0;
    if (requested > limit)
        return limit;
    return requested;
}

signed char target_speed(signed char requested, signed char limit)
{
    if (requested <= 0) {
        return 0;
    } else if (requested < 20) {
        return limit_speed(20, limit);
    } else {
        return limit_speed(requested, limit);
    }
}

signed char fan_command(signed char requested, signed char limit, unsigned char mode)
{
    if (mode == 1) {
        signed char normal = target_speed(requested, limit);
        return normal;
    } else if (mode == 2) {
        signed char boost = target_speed(limit, limit);
        return boost;
    } else {
        return 0;
    }
}
